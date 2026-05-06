from __future__ import annotations

from copy import deepcopy
from typing import Any

from graph_db.neo4j_manager import Neo4jGraphManager
from streamline.backend.models import GraphDelta


class StreamGraphState:
    def __init__(self, technique_name: str = "LIVE_SYSMON") -> None:
        self.technique_name = str(technique_name or "LIVE_SYSMON").strip() or "LIVE_SYSMON"
        self.technique_id = f"Technique:{self.technique_name}"

        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}

        self.triplet_count = 0
        self.relation_edge_count = 0
        self.root_edge_count = 0
        self.process_create_child_ids: set[str] = set()  # only tracks event_id=1 parent-child

        self._ensure_technique_node()

    def _ensure_technique_node(self) -> None:
        if self.technique_id in self.nodes:
            return
        self.nodes[self.technique_id] = {
            "id": self.technique_id,
            "label": self.technique_name,
            "group": "Technique",
            "type": "technique",
            "properties": {
                "id": self.technique_id,
                "type": "Technique",
                "entity_class": "Technique",
                "display_name": self.technique_name,
                "name": self.technique_name,
            },
        }

    def _entity_to_node(self, entity: Any) -> dict[str, Any]:
        payload = Neo4jGraphManager._build_entity_payload(entity)
        label = str(payload.get("label", "UnknownEntity") or "UnknownEntity")
        return {
            "id": payload["id"],
            "label": str(payload["properties"].get("display_name") or payload["id"]),
            "group": label,
            "type": label.lower(),
            "properties": payload["properties"],
        }

    def _build_relation_edge_id(self) -> str:
        self.triplet_count += 1
        return f"edge:{self.technique_name}:{self.triplet_count}"

    def _relation_edge(self, edge_id: str, source_id: str, target_id: str, action: str, event_id: str, timestamp: str) -> dict[str, Any]:
        relation = str(action or "RELATED_TO").strip() or "RELATED_TO"
        return {
            "id": edge_id,
            "from": source_id,
            "to": target_id,
            "source": source_id,
            "target": target_id,
            "label": relation,
            "type": relation,
            "properties": {
                "action": relation,
                "event_id": str(event_id or ""),
                "timestamp": str(timestamp or ""),
            },
        }

    def _root_edge(self, root_node_id: str) -> dict[str, Any]:
        return {
            "id": f"edge:{self.technique_name}:root:{root_node_id}",
            "from": self.technique_id,
            "to": root_node_id,
            "source": self.technique_id,
            "target": root_node_id,
            "label": "HAS_ROOT",
            "type": "HAS_ROOT",
            "properties": {
                "action": "HAS_ROOT",
                "event_id": "",
                "timestamp": "",
            },
        }

    def stats(self) -> dict[str, Any]:
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "relation_edges": self.relation_edge_count,
            "root_edges": self.root_edge_count,
            "triplets": self.triplet_count,
            "raw_events": self.triplet_count,
            "roots": self.root_edge_count,
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "technique": self.technique_name,
            "nodes": [deepcopy(node) for node in self.nodes.values()],
            "edges": [deepcopy(edge) for edge in self.edges.values()],
            "stats": self.stats(),
        }

    def apply_triplet(self, triplet: Any) -> GraphDelta:
        delta = GraphDelta()
        self._ensure_technique_node()

        if not triplet or not getattr(triplet, "subject", None) or not getattr(triplet, "object", None):
            delta.stats = self.stats()
            return delta

        subject_node = self._entity_to_node(triplet.subject)
        object_node = self._entity_to_node(triplet.object)

        for node in (subject_node, object_node):
            node_id = str(node["id"])
            existing = self.nodes.get(node_id)
            if not existing:
                self.nodes[node_id] = node
                delta.added_nodes.append(deepcopy(node))
                continue

            if existing != node:
                self.nodes[node_id] = node
                delta.updated_nodes.append(deepcopy(node))

        relation_edge = self._relation_edge(
            edge_id=self._build_relation_edge_id(),
            source_id=str(subject_node["id"]),
            target_id=str(object_node["id"]),
            action=str(getattr(triplet, "action", "") or "RELATED_TO"),
            event_id=str(getattr(triplet, "event_id", "") or ""),
            timestamp=str(getattr(triplet, "timestamp", "") or ""),
        )
        self.edges[relation_edge["id"]] = relation_edge
        self.relation_edge_count += 1
        delta.added_edges.append(deepcopy(relation_edge))

        subject_id = str(subject_node["id"])
        object_id = str(object_node["id"])
        is_process_create = str(getattr(triplet, "event_id", "")) == "1"

        # Only track parent-child from Process Create events; other relations
        # (ProcessAccess, Network, etc.) must not block HAS_ROOT assignment.
        if is_process_create and object_id not in self.process_create_child_ids:
            self.process_create_child_ids.add(object_id)
            removed_root_id = f"edge:{self.technique_name}:root:{object_id}"
            if removed_root_id in self.edges:
                del self.edges[removed_root_id]
                self.root_edge_count -= 1
                delta.removed_edge_ids.append(removed_root_id)

        # Add HAS_ROOT to subject if it has no Process Create parent
        if subject_id not in self.process_create_child_ids:
            root_edge = self._root_edge(subject_id)
            if root_edge["id"] not in self.edges:
                self.edges[root_edge["id"]] = root_edge
                self.root_edge_count += 1
                delta.added_edges.append(deepcopy(root_edge))

        delta.stats = self.stats()
        return delta
