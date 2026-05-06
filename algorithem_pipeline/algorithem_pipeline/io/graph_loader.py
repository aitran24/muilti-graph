from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import GraphData, GraphEdge, GraphNode


def _normalize_node(payload: dict[str, Any]) -> GraphNode | None:
    node_id = str(payload.get("id", "")).strip()
    if not node_id:
        return None
    return GraphNode(
        id=node_id,
        label=str(payload.get("label") or payload.get("name") or node_id),
        node_type=str(payload.get("type") or payload.get("node_type") or "unknown").lower(),
        group=str(payload.get("group") or "Unknown"),
        properties=dict(payload.get("properties") or {}),
    )


def _normalize_edge(payload: dict[str, Any], fallback_id: int) -> GraphEdge | None:
    source = str(payload.get("source") or payload.get("from") or "").strip()
    target = str(payload.get("target") or payload.get("to") or "").strip()
    if not source or not target:
        return None

    edge_id = str(payload.get("id") or f"edge:{fallback_id}")
    label = str(payload.get("label") or payload.get("type") or "RELATED_TO")
    edge_type = str(payload.get("type") or label or "RELATED_TO")

    return GraphEdge(
        id=edge_id,
        source=source,
        target=target,
        edge_type=edge_type,
        label=label,
        properties=dict(payload.get("properties") or {}),
    )


def load_graph_file(file_path: Path) -> GraphData:
    payload = json.loads(file_path.read_text(encoding="utf-8-sig"))
    return load_graph_payload(payload, name=file_path.name)


def load_graph_payload(payload: dict[str, Any], name: str = "graph.json") -> GraphData:
    node_map: dict[str, GraphNode] = {}
    for node_raw in payload.get("nodes", []):
        node = _normalize_node(node_raw)
        if node:
            node_map[node.id] = node

    edges: list[GraphEdge] = []
    for idx, edge_raw in enumerate(payload.get("edges", []), start=1):
        edge = _normalize_edge(edge_raw, idx)
        if edge:
            edges.append(edge)

    technique = str(payload.get("technique") or "").strip()
    if not technique:
        technique = Path(name).stem

    return GraphData(
        name=name,
        technique=technique,
        nodes=node_map,
        edges=edges,
        raw_payload=payload,
    )


def load_pattern_catalog(pattern_dir: Path) -> dict[str, GraphData]:
    catalog: dict[str, GraphData] = {}
    if not pattern_dir.exists():
        return catalog

    for file_path in sorted(pattern_dir.glob("*.json")):
        try:
            graph = load_graph_file(file_path)
        except Exception:
            continue
        catalog[graph.technique] = graph

    return catalog


def list_target_graph_files(target_dir: Path) -> list[Path]:
    if not target_dir.exists():
        return []
    return sorted(target_dir.glob("*.json"))
