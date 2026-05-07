from __future__ import annotations

import json
from typing import Any


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _clone_node(node: dict[str, Any]) -> dict[str, Any]:
    return {
        **node,
        "properties": {**(node.get("properties") or {})},
    }


def _clone_edge(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        **edge,
        "properties": {**(edge.get("properties") or {})},
    }


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value)
    if isinstance(value, dict):
        return bool(value)
    return True


def _is_identifier_like_key(key: str) -> bool:
    normalized = _normalize_text(key)
    if not normalized:
        return False

    if (
        normalized == "id"
        or normalized == "pid"
        or normalized == "guid"
        or normalized.endswith("_id")
        or "guid" in normalized
        or normalized.endswith("pid")
        or normalized.endswith("processid")
        or normalized.endswith("threadid")
        or normalized.endswith("recordid")
    ):
        return True

    return False


def _normalize_for_signature(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_for_signature(item) for item in value]

    if isinstance(value, dict):
        return {
            key: _normalize_for_signature(value[key])
            for key in sorted(value.keys(), key=str)
        }

    if isinstance(value, str):
        return value.strip().lower()

    return value


def _sanitize_object_for_merge_signature(payload: Any) -> Any:
    if isinstance(payload, list):
        return [_sanitize_object_for_merge_signature(item) for item in payload]

    if not isinstance(payload, dict):
        return payload

    sanitized: dict[str, Any] = {}
    for key, value in payload.items():
        if _is_identifier_like_key(key):
            continue
        sanitized[key] = _sanitize_object_for_merge_signature(value)

    return sanitized


def _stable_stringify(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _make_node_signature(node: dict[str, Any]) -> str:
    payload = {
        "group": node.get("group") or "",
        "type": node.get("type") or "",
        "label": node.get("label") or "",
        "properties": _sanitize_object_for_merge_signature(node.get("properties") or {}),
    }
    return _stable_stringify(_normalize_for_signature(payload))


def _normalize_relation_type(edge: dict[str, Any]) -> str:
    return str(
        edge.get("type")
        or edge.get("label")
        or ((edge.get("properties") or {}).get("action") or "")
    ).strip()


def _normalize_edge_shape(edge: dict[str, Any]) -> dict[str, Any]:
    source = str(edge.get("source") or edge.get("from") or "").strip()
    target = str(edge.get("target") or edge.get("to") or "").strip()
    relation = _normalize_relation_type(edge) or "RELATED_TO"
    edge_id = str(edge.get("id") or f"{source}::{target}::{relation}")

    return {
        **_clone_edge(edge),
        "id": edge_id,
        "source": source,
        "target": target,
        "from": source,
        "to": target,
        "label": relation,
        "type": relation,
        "properties": {
            **(edge.get("properties") or {}),
            "action": relation,
        },
    }


def _merge_object_latest(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = {**(existing or {})}

    for key, incoming_value in (incoming or {}).items():
        current_value = merged.get(key)

        if isinstance(current_value, dict) and isinstance(incoming_value, dict):
            merged[key] = _merge_object_latest(current_value, incoming_value)
            continue

        if _is_meaningful_value(incoming_value) or not _is_meaningful_value(current_value):
            merged[key] = incoming_value

    return merged


def _merge_node_latest(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    existing_clone = _clone_node(existing)
    incoming_clone = _clone_node(incoming)

    merged = {
        **existing_clone,
        **incoming_clone,
        "id": existing_clone.get("id"),
    }

    merged["properties"] = _merge_object_latest(
        existing_clone.get("properties") or {},
        incoming_clone.get("properties") or {},
    )

    incoming_label = incoming_clone.get("label")
    if _is_meaningful_value(incoming_label):
        merged["label"] = incoming_label
    elif _is_meaningful_value((merged.get("properties") or {}).get("display_name")):
        merged["label"] = (merged.get("properties") or {}).get("display_name")

    return merged


def _merge_edge_latest(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    existing_clone = _clone_edge(existing)
    incoming_clone = _clone_edge(incoming)

    source = existing_clone.get("source")
    target = existing_clone.get("target")

    merged = {
        **existing_clone,
        **incoming_clone,
        "id": existing_clone.get("id"),
        "source": source,
        "target": target,
        "from": source,
        "to": target,
    }

    merged["properties"] = _merge_object_latest(
        existing_clone.get("properties") or {},
        incoming_clone.get("properties") or {},
    )

    return merged


def _resolve_redirect(node_id: str, redirect_map: dict[str, str]) -> str:
    current = str(node_id or "").strip()
    visited: set[str] = set()

    while current and current in redirect_map and current not in visited:
        visited.add(current)
        current = redirect_map[current]

    return current


def _apply_redirects_to_edges(
    edges: list[dict[str, Any]],
    redirect_map: dict[str, str],
) -> list[dict[str, Any]]:
    normalized = [_normalize_edge_shape(edge) for edge in edges or []]

    redirected: list[dict[str, Any]] = []
    for edge in normalized:
        source = _resolve_redirect(str(edge.get("source") or ""), redirect_map)
        target = _resolve_redirect(str(edge.get("target") or ""), redirect_map)
        if not source or not target or source == target:
            continue

        redirected.append(
            {
                **edge,
                "source": source,
                "target": target,
                "from": source,
                "to": target,
            }
        )

    return redirected


def _dedupe_edges_latest(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edge_map: dict[str, dict[str, Any]] = {}

    for edge in edges or []:
        normalized_edge = _normalize_edge_shape(edge)
        source = str(normalized_edge.get("source") or "").strip()
        target = str(normalized_edge.get("target") or "").strip()
        if not source or not target or source == target:
            continue

        relation = _normalize_text(normalized_edge.get("label") or normalized_edge.get("type") or "RELATED_TO")
        dedupe_key = f"{source}::{target}::{relation}"

        if dedupe_key not in edge_map:
            edge_map[dedupe_key] = normalized_edge
            continue

        edge_map[dedupe_key] = _merge_edge_latest(edge_map[dedupe_key], normalized_edge)

    return list(edge_map.values())


def is_technique_node(node: dict[str, Any]) -> bool:
    return _normalize_text(node.get("type") or node.get("group")) == "technique"


def is_process_node(node: dict[str, Any]) -> bool:
    node_type = _normalize_text(node.get("type"))
    group_type = _normalize_text(node.get("group"))
    return node_type == "process" or group_type == "process"


def build_pruned_graph(graph: dict[str, Any]) -> dict[str, Any]:
    raw_nodes = list(graph.get("nodes") or [])
    raw_edges = list(graph.get("edges") or [])

    node_map: dict[str, dict[str, Any]] = {}
    for node in raw_nodes:
        cloned = _clone_node(node)
        node_id = str(cloned.get("id") or "").strip()
        if not node_id:
            continue
        cloned["id"] = node_id
        node_map[node_id] = cloned

    redirect_map: dict[str, str] = {}

    process_signature_to_canonical_id: dict[str, str] = {}
    for raw_node in raw_nodes:
        node_id = str((raw_node or {}).get("id") or "").strip()
        if not node_id:
            continue

        node = node_map.get(node_id)
        if not node or not is_process_node(node):
            continue

        signature = _make_node_signature(node)
        canonical_id = process_signature_to_canonical_id.get(signature)
        if not canonical_id:
            process_signature_to_canonical_id[signature] = node_id
            continue

        if canonical_id == node_id:
            continue

        redirect_map[node_id] = canonical_id
        node_map[canonical_id] = _merge_node_latest(node_map[canonical_id], node)
        node_map.pop(node_id, None)

    process_merged_edges = _dedupe_edges_latest(_apply_redirects_to_edges(raw_edges, redirect_map))

    process_node_ids = {
        node_id
        for node_id, node in node_map.items()
        if is_process_node(node)
    }

    relation_merge_groups: dict[str, str] = {}
    for edge in process_merged_edges:
        source_id = str(edge.get("source") or edge.get("from") or "").strip()
        target_id = str(edge.get("target") or edge.get("to") or "").strip()
        if not source_id or not target_id:
            continue

        source_is_process = source_id in process_node_ids
        target_is_process = target_id in process_node_ids
        if source_is_process == target_is_process:
            continue

        process_id = source_id if source_is_process else target_id
        related_id = target_id if source_is_process else source_id
        related_node = node_map.get(related_id)
        if not related_node or is_process_node(related_node) or is_technique_node(related_node):
            continue

        direction = "out" if source_is_process else "in"
        relation = _normalize_text(edge.get("label") or edge.get("type") or "RELATED_TO")
        signature = _make_node_signature(related_node)
        merge_key = f"{process_id}::{direction}::{relation}::{signature}"

        canonical_related_id = relation_merge_groups.get(merge_key)
        if not canonical_related_id:
            relation_merge_groups[merge_key] = related_id
            continue

        if canonical_related_id == related_id:
            continue

        redirect_map[related_id] = canonical_related_id
        node_map[canonical_related_id] = _merge_node_latest(node_map[canonical_related_id], related_node)
        node_map.pop(related_id, None)

    final_edges = _dedupe_edges_latest(_apply_redirects_to_edges(process_merged_edges, redirect_map))

    referenced_node_ids: set[str] = set()
    for edge in final_edges:
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if source:
            referenced_node_ids.add(source)
        if target:
            referenced_node_ids.add(target)

    final_nodes: list[dict[str, Any]] = []
    for node_id, node in node_map.items():
        if node_id in referenced_node_ids or is_technique_node(node):
            final_nodes.append(node)

    return {
        "nodes": final_nodes,
        "edges": final_edges,
    }
