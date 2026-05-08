from __future__ import annotations

import copy
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inspect_log_gui.backend.pipeline import TechniqueGraphPipeline  # noqa: E402
from inspect_log_gui.backend.storage import PatternStore  # noqa: E402


@dataclass
class GraphIndex:
    node_map: dict[str, dict[str, Any]]
    relation_edges: list[dict[str, Any]]
    root_edges: list[dict[str, Any]]
    children_map: dict[str, set[str]]
    parent_map: dict[str, set[str]]
    technique_node_ids: set[str]


class PureAttackTreePipeline:
    """
    Build and persist a pure attack tree per technique.

    Flow:
    1. Reuse the original inspect GUI pipeline to build full graph.
    2. Match malicious/whitelist patterns on every node payload field.
    3. Prune graph using attack-tree rules.
    4. Save result under clean_attack_tree/<technique>.json.
    """

    _SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]")

    def __init__(self, dataset_folder: Path, data_dir: Path, output_dir: Path):
        self.dataset_folder = dataset_folder
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._full_graph_pipeline = TechniqueGraphPipeline(dataset_folder=self.dataset_folder)
        self._pattern_store = PatternStore(data_dir=self.data_dir)

    @staticmethod
    def _sanitize_name(value: str) -> str:
        token = PureAttackTreePipeline._SAFE_NAME_RE.sub("_", (value or "").strip())
        return token or "technique"

    @staticmethod
    def _is_has_root_edge(edge: dict[str, Any]) -> bool:
        edge_type = str(edge.get("type") or edge.get("label") or "").strip().upper()
        return edge_type == "HAS_ROOT"

    @staticmethod
    def _normalize_slashes(value: str) -> str:
        if "/" not in value and "\\" not in value:
            return value
        converted = value.replace("/", "\\")
        # Keep slash behavior consistent with parser-normalized command/path fields.
        parts = [part for part in converted.split("\\") if part]
        if not parts:
            return converted
        return "\\".join(parts)

    @staticmethod
    def _normalize_patterns(patterns: Any) -> list[str]:
        if not isinstance(patterns, list):
            return []

        normalized: list[str] = []
        seen: set[str] = set()
        for item in patterns:
            value = str(item or "").strip()
            # Collapse over-escaped backslashes before matching/pruning.
            if "\\\\" in value:
                value = value.replace("\\\\", "\\")
            value = PureAttackTreePipeline._normalize_slashes(value)
            value = value.lower()
            if not value or value in seen:
                continue
            seen.add(value)
            normalized.append(value)
        return normalized

    @staticmethod
    def _node_search_blob(node: dict[str, Any]) -> str:
        payload = {
            "id": node.get("id", ""),
            "label": node.get("label", ""),
            "type": node.get("type", ""),
            "group": node.get("group", ""),
            "properties": node.get("properties", {}),
        }
        return json.dumps(payload, ensure_ascii=False, default=str).lower()

    @staticmethod
    def _match_node_ids(
        node_map: dict[str, dict[str, Any]],
        patterns: list[str],
    ) -> set[str]:
        if not patterns:
            return set()

        matched: set[str] = set()
        for node_id, node in node_map.items():
            blob = PureAttackTreePipeline._node_search_blob(node)
            if any(pattern in blob for pattern in patterns):
                matched.add(node_id)
        return matched

    @staticmethod
    def _collect_descendants(start_ids: Iterable[str], children_map: dict[str, set[str]]) -> set[str]:
        visited: set[str] = set()
        stack = [node_id for node_id in start_ids if node_id]

        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for child_id in children_map.get(current, set()):
                if child_id not in visited:
                    stack.append(child_id)

        return visited

    @staticmethod
    def _collect_ancestors(start_ids: Iterable[str], parent_map: dict[str, set[str]]) -> set[str]:
        visited: set[str] = set()
        stack = [node_id for node_id in start_ids if node_id]

        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for parent_id in parent_map.get(current, set()):
                if parent_id not in visited:
                    stack.append(parent_id)

        return visited

    @staticmethod
    def _collect_path_to_ancestor(
        start_id: str,
        ancestor_id: str,
        parent_map: dict[str, set[str]],
        allowed_nodes: set[str],
    ) -> set[str]:
        # Collect all nodes on all possible parent paths within the allowed scope.
        required: set[str] = set()
        stack = [start_id]

        while stack:
            current = stack.pop()
            if current in required:
                continue
            required.add(current)

            if current == ancestor_id:
                continue

            for parent_id in parent_map.get(current, set()):
                if parent_id in allowed_nodes and parent_id not in required:
                    stack.append(parent_id)

        return required

    @staticmethod
    def _build_index(graph: dict[str, Any]) -> GraphIndex:
        nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
        edges = graph.get("edges", []) if isinstance(graph, dict) else []

        node_map: dict[str, dict[str, Any]] = {}
        for node in nodes:
            node_id = str(node.get("id", "")).strip()
            if not node_id:
                continue
            node_map[node_id] = node

        relation_edges: list[dict[str, Any]] = []
        root_edges: list[dict[str, Any]] = []
        children_map: dict[str, set[str]] = {}
        parent_map: dict[str, set[str]] = {}

        for edge in edges:
            source_id = str(edge.get("source") or edge.get("from") or "").strip()
            target_id = str(edge.get("target") or edge.get("to") or "").strip()
            if not source_id or not target_id:
                continue

            if PureAttackTreePipeline._is_has_root_edge(edge):
                root_edges.append(edge)
                continue

            relation_edges.append(edge)
            children_map.setdefault(source_id, set()).add(target_id)
            parent_map.setdefault(target_id, set()).add(source_id)

        technique_node_ids = {
            node_id
            for node_id, node in node_map.items()
            if str(node.get("type", "")).lower() == "technique"
            or str(node.get("group", "")).lower() == "technique"
        }

        return GraphIndex(
            node_map=node_map,
            relation_edges=relation_edges,
            root_edges=root_edges,
            children_map=children_map,
            parent_map=parent_map,
            technique_node_ids=technique_node_ids,
        )

    def _apply_whitelist_rules(
        self,
        keep_nontech_node_ids: set[str],
        malicious_node_ids: set[str],
        whitelist_node_ids: set[str],
        has_malicious_in_subtree: set[str],
        children_map: dict[str, set[str]],
        parent_map: dict[str, set[str]],
        preserve_whitelist_anchor: bool = False,
    ) -> set[str]:
        keep = set(keep_nontech_node_ids)

        # Pass 1: drop every whitelist subtree that has no malicious descendant.
        for whitelist_id in sorted(whitelist_node_ids):
            if whitelist_id not in keep:
                continue
            if whitelist_id in malicious_node_ids:
                continue
            if whitelist_id in has_malicious_in_subtree:
                continue

            removable = self._collect_descendants([whitelist_id], children_map)
            if preserve_whitelist_anchor:
                removable.discard(whitelist_id)
            keep.difference_update(removable)

        # Pass 2: whitelist node with malicious descendant keeps only malicious-relevant branches.
        for whitelist_id in sorted(whitelist_node_ids):
            if whitelist_id not in keep:
                continue
            if whitelist_id in malicious_node_ids:
                continue
            if whitelist_id not in has_malicious_in_subtree:
                continue

            subtree_nodes = self._collect_descendants([whitelist_id], children_map)
            subtree_nodes.add(whitelist_id)

            malicious_in_scope = [
                node_id
                for node_id in malicious_node_ids
                if node_id in subtree_nodes and node_id in keep
            ]
            if not malicious_in_scope:
                keep.discard(whitelist_id)
                keep.difference_update(subtree_nodes)
                continue

            required: set[str] = {whitelist_id}
            for malicious_id in malicious_in_scope:
                required.update(self._collect_descendants([malicious_id], children_map))
                required.update(
                    self._collect_path_to_ancestor(
                        start_id=malicious_id,
                        ancestor_id=whitelist_id,
                        parent_map=parent_map,
                        allowed_nodes=subtree_nodes,
                    )
                )

            for node_id in subtree_nodes:
                if node_id not in keep:
                    continue
                if node_id in required:
                    continue
                if node_id in malicious_node_ids:
                    continue
                keep.discard(node_id)

        return keep

    def _apply_bidirectional_whitelist_rules(
        self,
        keep_nontech_node_ids: set[str],
        malicious_node_ids: set[str],
        whitelist_node_ids: set[str],
        children_map: dict[str, set[str]],
        parent_map: dict[str, set[str]],
        max_passes: int = 8,
    ) -> set[str]:
        keep = set(keep_nontech_node_ids)
        if not keep or not whitelist_node_ids:
            return keep

        has_malicious_in_lower_subtree = self._collect_ancestors(malicious_node_ids, parent_map)
        has_malicious_in_upper_subtree = self._collect_ancestors(malicious_node_ids, children_map)

        for _ in range(max_passes):
            previous = set(keep)

            keep = self._apply_whitelist_rules(
                keep_nontech_node_ids=keep,
                malicious_node_ids=malicious_node_ids,
                whitelist_node_ids=whitelist_node_ids,
                has_malicious_in_subtree=has_malicious_in_lower_subtree,
                children_map=children_map,
                parent_map=parent_map,
                preserve_whitelist_anchor=False,
            )

            # Mirror whitelist pruning on parent-side branches. When a whitelist
            # anchor has no malicious match above it, drop only the upper branch
            # and let HAS_ROOT rewiring attach the anchor to Technique.
            keep = self._apply_whitelist_rules(
                keep_nontech_node_ids=keep,
                malicious_node_ids=malicious_node_ids,
                whitelist_node_ids=whitelist_node_ids,
                has_malicious_in_subtree=has_malicious_in_upper_subtree,
                children_map=parent_map,
                parent_map=children_map,
                preserve_whitelist_anchor=True,
            )

            if keep == previous:
                break

        return keep

    @staticmethod
    def _filter_edges_by_nodes(
        edges: list[dict[str, Any]],
        allowed_nodes: set[str],
    ) -> list[dict[str, Any]]:
        kept_edges: list[dict[str, Any]] = []
        for edge in edges:
            source_id = str(edge.get("source") or edge.get("from") or "").strip()
            target_id = str(edge.get("target") or edge.get("to") or "").strip()
            if source_id in allowed_nodes and target_id in allowed_nodes:
                kept_edges.append(edge)
        return kept_edges

    @staticmethod
    def _ensure_root_edges(
        technique_id: str,
        technique: str,
        relation_edges: list[dict[str, Any]],
        root_edges: list[dict[str, Any]],
        kept_nontech_node_ids: set[str],
    ) -> list[dict[str, Any]]:
        kept_root_edges = [
            edge
            for edge in root_edges
            if str(edge.get("source") or edge.get("from") or "") == technique_id
            and str(edge.get("target") or edge.get("to") or "") in kept_nontech_node_ids
        ]

        if not kept_nontech_node_ids:
            return kept_root_edges

        indegree: dict[str, int] = {node_id: 0 for node_id in kept_nontech_node_ids}
        undirected_neighbors: dict[str, set[str]] = {node_id: set() for node_id in kept_nontech_node_ids}
        for edge in relation_edges:
            source_id = str(edge.get("source") or edge.get("from") or "").strip()
            target_id = str(edge.get("target") or edge.get("to") or "").strip()
            if source_id in undirected_neighbors and target_id in undirected_neighbors:
                undirected_neighbors[source_id].add(target_id)
                undirected_neighbors[target_id].add(source_id)
            if target_id in indegree:
                indegree[target_id] += 1

        components: list[set[str]] = []
        visited: set[str] = set()
        for node_id in sorted(kept_nontech_node_ids):
            if node_id in visited:
                continue

            stack = [node_id]
            component: set[str] = set()
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)
                for neighbor in undirected_neighbors.get(current, set()):
                    if neighbor not in visited:
                        stack.append(neighbor)

            components.append(component)

        existing_root_targets = {
            str(edge.get("target") or edge.get("to") or "").strip() for edge in kept_root_edges
        }

        generated_edges: list[dict[str, Any]] = []
        for component in components:
            if component & existing_root_targets:
                continue

            zero_indegree_candidates = sorted(
                node_id for node_id in component if indegree.get(node_id, 0) == 0
            )
            if zero_indegree_candidates:
                root_id = zero_indegree_candidates[0]
            else:
                root_id = sorted(component)[0]

            generated_edges.append(
                {
                    "id": f"edge:{technique}:pure_root:{root_id}",
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
            )
            existing_root_targets.add(root_id)

        return kept_root_edges + generated_edges

    def _build_pure_attack_graph(self, technique: str, source_graph: dict[str, Any]) -> dict[str, Any]:
        index = self._build_index(source_graph)

        malicious_patterns = self._normalize_patterns(self._pattern_store.get_patterns(technique))
        whitelist_patterns = self._normalize_patterns(self._pattern_store.get_whitelist(technique))

        non_technique_node_ids = {
            node_id for node_id in index.node_map.keys() if node_id not in index.technique_node_ids
        }

        raw_malicious_node_ids = self._match_node_ids(
            {node_id: index.node_map[node_id] for node_id in non_technique_node_ids},
            malicious_patterns,
        )
        whitelist_node_ids = self._match_node_ids(
            {node_id: index.node_map[node_id] for node_id in non_technique_node_ids},
            whitelist_patterns,
        )

        # Whitelist wins on overlap: node matched by both sides is treated as whitelist.
        overlap_node_ids = raw_malicious_node_ids & whitelist_node_ids
        malicious_node_ids = raw_malicious_node_ids - overlap_node_ids

        # Core Effect: manually-configured patterns stored under "core_effect" in the
        # config file. Identifies the direct attack component (not launcher/parent).
        core_effect_patterns = self._normalize_patterns(self._pattern_store.get_core_effect(technique))
        core_effect_node_ids = self._match_node_ids(
            {node_id: index.node_map[node_id] for node_id in non_technique_node_ids},
            core_effect_patterns,
        )

        if malicious_node_ids:
            malicious_descendants = self._collect_descendants(malicious_node_ids, index.children_map)
            malicious_ancestors = self._collect_ancestors(malicious_node_ids, index.parent_map)
            keep_nontech_node_ids = (malicious_descendants | malicious_ancestors) & non_technique_node_ids
        else:
            keep_nontech_node_ids = set()

        keep_nontech_node_ids = self._apply_bidirectional_whitelist_rules(
            keep_nontech_node_ids=keep_nontech_node_ids,
            malicious_node_ids=malicious_node_ids,
            whitelist_node_ids=whitelist_node_ids,
            children_map=index.children_map,
            parent_map=index.parent_map,
        )

        kept_relation_edges = self._filter_edges_by_nodes(index.relation_edges, keep_nontech_node_ids)

        technique_node_ids = set(index.technique_node_ids)
        if not technique_node_ids:
            synthetic_technique = TechniqueGraphPipeline._build_technique_node(technique)  # type: ignore[attr-defined]
            index.node_map[synthetic_technique["id"]] = synthetic_technique
            technique_node_ids.add(synthetic_technique["id"])

        primary_technique_id = sorted(technique_node_ids)[0]
        kept_root_edges = self._ensure_root_edges(
            technique_id=primary_technique_id,
            technique=technique,
            relation_edges=kept_relation_edges,
            root_edges=index.root_edges,
            kept_nontech_node_ids=keep_nontech_node_ids,
        )

        kept_node_ids = keep_nontech_node_ids | technique_node_ids
        kept_nodes = [copy.deepcopy(index.node_map[node_id]) for node_id in kept_node_ids if node_id in index.node_map]
        kept_edges = [copy.deepcopy(edge) for edge in (kept_relation_edges + kept_root_edges)]

        pruned_graph = {
            "schema_version": 1,
            "kind": "pure_attack_tree",
            "technique": technique,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_file": source_graph.get("source_file", ""),
            "source_files": source_graph.get("source_files", []),
            "patterns": {
                "malicious": malicious_patterns,
                "whitelist": whitelist_patterns,
                "core_effect": core_effect_patterns,
                "config_path": str(self.data_dir / f"{self._sanitize_name(technique)}_malcious_config.json"),
            },
            "matching": {
                "malicious_node_ids": sorted(malicious_node_ids),
                "core_effect_node_ids": sorted(core_effect_node_ids),
                "whitelist_node_ids": sorted(whitelist_node_ids),
                "overlap_whitelist_override_node_ids": sorted(overlap_node_ids),
            },
            "nodes": kept_nodes,
            "edges": kept_edges,
            "stats": {
                "source_nodes": len(index.node_map),
                "source_edges": len(index.relation_edges) + len(index.root_edges),
                "attack_nodes": len(kept_nodes),
                "attack_edges": len(kept_edges),
                "roots": len(kept_root_edges),
                "matched_malicious_nodes": len(malicious_node_ids),
                "core_effect_nodes": len(core_effect_node_ids),
                "matched_whitelist_nodes": len(whitelist_node_ids),
                "matched_overlap_whitelist_override_nodes": len(overlap_node_ids),
            },
        }

        return pruned_graph

    def output_file_path(self, technique: str) -> Path:
        return self.output_dir / f"{self._sanitize_name(technique)}.json"

    def has_saved_graph(self, technique: str) -> bool:
        return self.output_file_path(technique).exists()

    def list_techniques(self) -> list[str]:
        return self._full_graph_pipeline.list_techniques()

    def load_saved_graph(self, technique: str) -> dict[str, Any]:
        output_file = self.output_file_path(technique)
        if not output_file.exists():
            raise FileNotFoundError(f"Pure attack tree for technique '{technique}' has not been generated yet.")

        try:
            payload = json.loads(output_file.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Failed to load saved pure attack tree: {output_file}") from exc

        if not isinstance(payload, dict):
            raise RuntimeError(f"Saved pure attack tree has invalid format: {output_file}")

        return payload

    def build_graph(self, technique: str) -> dict[str, Any]:
        source_graph = self._full_graph_pipeline.build_graph(technique)
        return self._build_pure_attack_graph(technique, source_graph)

    def build_and_save(self, technique: str) -> dict[str, Any]:
        graph = self.build_graph(technique)
        output_file = self.output_file_path(technique)
        output_file.write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")
        return graph

    def get_graph(self, technique: str, rebuild: bool = False) -> dict[str, Any]:
        if rebuild or not self.has_saved_graph(technique):
            return self.build_and_save(technique)
        return self.load_saved_graph(technique)

    def build_all(self, techniques: list[str] | None = None, force_rebuild: bool = False) -> dict[str, Any]:
        selected = techniques or self.list_techniques()

        built: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        for technique in selected:
            try:
                graph = self.get_graph(technique, rebuild=force_rebuild)
                built.append(
                    {
                        "technique": technique,
                        "output_file": str(self.output_file_path(technique)),
                        "nodes": len(graph.get("nodes", [])),
                        "edges": len(graph.get("edges", [])),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                errors.append({"technique": technique, "error": str(exc)})

        return {
            "requested": len(selected),
            "built": len(built),
            "failed": len(errors),
            "results": built,
            "errors": errors,
            "output_folder": str(self.output_dir),
        }
