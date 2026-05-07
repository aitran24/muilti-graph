from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from threading import Lock
from typing import Any

from algorithem_pipeline.algorithem_pipeline.algorithms import (
    BaselineExactMatcher,
    BehavioralAnchorFusionMatcher,
    CoreApproximateMatcher,
    ScaleMultiPatternMatcher,
    StructureAdaptiveMatcher,
)
from algorithem_pipeline.algorithem_pipeline.evaluation.benchmark import run_benchmark
from algorithem_pipeline.algorithem_pipeline.io.graph_loader import (
    load_graph_payload,
    load_pattern_catalog,
)

from streamline.backend.prune_graph import build_pruned_graph


@dataclass(slots=True)
class _MatchEntry:
    key: str
    algorithm: str
    technique: str
    score: float
    runtime_ms: float
    notes: str
    matched_node_ids: list[str]


@dataclass(slots=True)
class _LiveMatchState:
    graph_revision: int = 0
    raw_graph: dict[str, Any] = field(default_factory=dict)
    pruned_graph: dict[str, Any] = field(default_factory=dict)
    public_payload: dict[str, Any] = field(default_factory=dict)
    match_index: dict[str, _MatchEntry] = field(default_factory=dict)


class LiveMatchEngine:
    """Run multi-technique matching on the backend using pruned live graph snapshots."""

    def __init__(
        self,
        repo_root: Path,
        algorithm_names: tuple[str, ...],
        top_k: int,
    ) -> None:
        self.repo_root = Path(repo_root)
        pattern_dir = self.repo_root / "inspect_log_gui" / "clean_attack_tree"
        self.catalog = load_pattern_catalog(pattern_dir)

        self._algorithms = {
            "baseline_exact": BaselineExactMatcher(),
            "core_approximate": CoreApproximateMatcher(),
            "scale_multipattern": ScaleMultiPatternMatcher(),
            "structure_adaptive": StructureAdaptiveMatcher(),
            "behavioral_anchor_fusion": BehavioralAnchorFusionMatcher(),
        }

        normalized_names = [
            name.strip() for name in algorithm_names if str(name or "").strip() in self._algorithms
        ]
        self.algorithm_names = normalized_names or [
            "core_approximate",
            "scale_multipattern",
            "structure_adaptive",
            "behavioral_anchor_fusion",
        ]
        self.top_k = max(1, int(top_k or 1))

        self._lock = Lock()
        self._state = _LiveMatchState()
        self._last_pruned_fingerprint = ""

    def _graph_stats(self, graph: dict[str, Any]) -> dict[str, int]:
        nodes = list(graph.get("nodes") or [])
        edges = list(graph.get("edges") or [])
        return {
            "nodes": len(nodes),
            "edges": len(edges),
        }

    def run(self, raw_graph: dict[str, Any], graph_revision: int) -> dict[str, Any]:
        safe_raw_graph = {
            "nodes": list((raw_graph or {}).get("nodes") or []),
            "edges": list((raw_graph or {}).get("edges") or []),
            "stats": dict((raw_graph or {}).get("stats") or {}),
            "technique": str((raw_graph or {}).get("technique") or "LIVE_SYSMON"),
        }
        pruned_graph = build_pruned_graph(safe_raw_graph)
        pruned_graph["technique"] = "LIVE_SYSMON_PRUNED"
        pruned_fingerprint = _fingerprint_graph(pruned_graph)

        with self._lock:
            if (
                self._last_pruned_fingerprint
                and self._last_pruned_fingerprint == pruned_fingerprint
                and self._state.public_payload
                and self._state.match_index
            ):
                cached_payload = deepcopy(self._state.public_payload)
                cached_payload["graph_revision"] = int(graph_revision)
                cached_payload["generated_at"] = datetime.now(timezone.utc).isoformat()
                cached_payload["raw_graph_stats"] = self._graph_stats(safe_raw_graph)
                cached_payload["pruned_graph_stats"] = self._graph_stats(pruned_graph)

                self._state = _LiveMatchState(
                    graph_revision=int(graph_revision),
                    raw_graph=deepcopy(safe_raw_graph),
                    pruned_graph=deepcopy(pruned_graph),
                    public_payload=deepcopy(cached_payload),
                    match_index=deepcopy(self._state.match_index),
                )
                return cached_payload

        target_graph = load_graph_payload(
            pruned_graph,
            name=f"live-pruned-rev-{graph_revision}.json",
        )

        algorithm_payloads: list[dict[str, Any]] = []
        match_index: dict[str, _MatchEntry] = {}

        for algorithm_name in self.algorithm_names:
            matcher = self._algorithms.get(algorithm_name)
            if matcher is None:
                continue

            matches = []
            for technique, pattern_graph in self.catalog.items():
                match = matcher.match(target_graph=target_graph, pattern_graph=pattern_graph)
                match.technique = technique
                matches.append(match)

            benchmark = run_benchmark(
                algorithm_name=algorithm_name,
                all_matches=matches,
                target_technique=target_graph.technique,
            )

            top_matches = benchmark.matches[: self.top_k]
            top_payload: list[dict[str, Any]] = []

            for rank, match in enumerate(top_matches, start=1):
                key = f"{algorithm_name}:{match.technique}"
                matched_ids = sorted({str(node_id) for node_id in match.matched_node_ids if str(node_id)})

                match_index[key] = _MatchEntry(
                    key=key,
                    algorithm=algorithm_name,
                    technique=match.technique,
                    score=float(match.score),
                    runtime_ms=float(match.runtime_ms),
                    notes=str(match.notes or ""),
                    matched_node_ids=matched_ids,
                )

                top_payload.append(
                    {
                        "key": key,
                        "rank": rank,
                        "technique": match.technique,
                        "score": float(match.score),
                        "runtime_ms": float(match.runtime_ms),
                        "matched_node_count": len(matched_ids),
                        "notes": str(match.notes or ""),
                    }
                )

            algorithm_payloads.append(
                {
                    "name": algorithm_name,
                    "runtime_ms": float(benchmark.runtime_ms),
                    "top1_technique": benchmark.top1_technique,
                    "top1_score": float(benchmark.top1_score),
                    "match_count": len(matches),
                    "top_matches": top_payload,
                }
            )

        public_payload = {
            "graph_revision": int(graph_revision),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "raw_graph_stats": self._graph_stats(safe_raw_graph),
            "pruned_graph_stats": self._graph_stats(pruned_graph),
            "algorithms": algorithm_payloads,
        }

        with self._lock:
            self._last_pruned_fingerprint = pruned_fingerprint
            self._state = _LiveMatchState(
                graph_revision=int(graph_revision),
                raw_graph=deepcopy(safe_raw_graph),
                pruned_graph=deepcopy(pruned_graph),
                public_payload=deepcopy(public_payload),
                match_index=match_index,
            )

        return public_payload

    def get_public_state(self) -> dict[str, Any] | None:
        with self._lock:
            if not self._state.public_payload:
                return None
            return deepcopy(self._state.public_payload)

    def get_pruned_graph_state(self) -> dict[str, Any] | None:
        with self._lock:
            if not self._state.pruned_graph:
                return None
            return {
                "graph_revision": self._state.graph_revision,
                "graph": deepcopy(self._state.pruned_graph),
                "stats": self._graph_stats(self._state.pruned_graph),
            }

    def get_context_for_key(self, key: str) -> dict[str, Any] | None:
        key_text = str(key or "").strip()
        if not key_text:
            return None

        with self._lock:
            entry = self._state.match_index.get(key_text)
            if entry is None:
                return None
            pruned_graph = deepcopy(self._state.pruned_graph)
            graph_revision = self._state.graph_revision

        context = _build_tree_context(pruned_graph, set(entry.matched_node_ids))
        return {
            "key": entry.key,
            "algorithm": entry.algorithm,
            "technique": entry.technique,
            "score": entry.score,
            "runtime_ms": entry.runtime_ms,
            "notes": entry.notes,
            "graph_revision": graph_revision,
            "matched_node_ids": list(entry.matched_node_ids),
            "highlight": context["highlight"],
            "trees": context["trees"],
            "subtrees": context["subtrees"],
            "tree_count": context["tree_count"],
            "subtree_count": context["subtree_count"],
        }

    def build_snapshot_payload(self, key: str, snapshot_id: str) -> dict[str, Any] | None:
        context = self.get_context_for_key(key)
        if context is None:
            return None

        with self._lock:
            pruned_graph = deepcopy(self._state.pruned_graph)

        return {
            "snapshot_id": snapshot_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "graph_revision": context["graph_revision"],
            "match": {
                "key": context["key"],
                "algorithm": context["algorithm"],
                "technique": context["technique"],
                "score": context["score"],
                "runtime_ms": context["runtime_ms"],
                "notes": context["notes"],
            },
            "matched_node_ids": context["matched_node_ids"],
            "highlight": context["highlight"],
            "trees": context["trees"],
            "subtrees": context["subtrees"],
            "graph": pruned_graph,
        }


def _edge_items(graph: dict[str, Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for index, edge in enumerate(list(graph.get("edges") or []), start=1):
        source = str(edge.get("source") or edge.get("from") or "").strip()
        target = str(edge.get("target") or edge.get("to") or "").strip()
        if not source or not target:
            continue

        edge_id = str(edge.get("id") or f"edge:{index}:{source}:{target}")
        edge_type = str(edge.get("type") or edge.get("label") or "RELATED_TO")

        normalized.append(
            {
                **edge,
                "id": edge_id,
                "source": source,
                "target": target,
                "type": edge_type,
            }
        )

    return normalized


def _root_ids(nodes: set[str], edges: list[dict[str, Any]]) -> list[str]:
    explicit_roots: list[str] = []
    incoming: dict[str, int] = {node_id: 0 for node_id in nodes}

    for edge in edges:
        edge_type = str(edge.get("type") or "").strip().upper()
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()

        if edge_type == "HAS_ROOT":
            if target in nodes:
                explicit_roots.append(target)
            continue

        if source in nodes and target in nodes:
            incoming[target] = incoming.get(target, 0) + 1

    if explicit_roots:
        seen: set[str] = set()
        ordered: list[str] = []
        for node_id in explicit_roots:
            if node_id in seen:
                continue
            seen.add(node_id)
            ordered.append(node_id)
        return ordered

    inferred = [node_id for node_id, count in incoming.items() if count <= 0]
    if inferred:
        return sorted(inferred)

    return sorted(nodes)


def _build_tree_context(graph: dict[str, Any], matched_node_ids: set[str]) -> dict[str, Any]:
    nodes = list(graph.get("nodes") or [])
    node_id_set = {
        str(node.get("id") or "").strip()
        for node in nodes
        if str(node.get("id") or "").strip()
    }

    edges = _edge_items(graph)

    children_map: dict[str, set[str]] = {}
    for edge in edges:
        edge_type = str(edge.get("type") or "").strip().upper()
        if edge_type == "HAS_ROOT":
            continue
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if source not in node_id_set or target not in node_id_set:
            continue
        children_map.setdefault(source, set()).add(target)

    roots = _root_ids(node_id_set, edges)
    valid_matched = sorted(node_id for node_id in matched_node_ids if node_id in node_id_set)

    descendants_cache: dict[str, set[str]] = {}

    def descendants(start_node: str) -> set[str]:
        if start_node in descendants_cache:
            return set(descendants_cache[start_node])

        visited: set[str] = set()
        stack = [start_node]
        while stack:
            current = stack.pop()
            if current in visited or current not in node_id_set:
                continue
            visited.add(current)
            for child in children_map.get(current, set()):
                if child not in visited:
                    stack.append(child)

        descendants_cache[start_node] = set(visited)
        return visited

    def edge_ids_for_nodes(selected_nodes: set[str]) -> list[str]:
        edge_ids: list[str] = []
        for edge in edges:
            source = str(edge.get("source") or "").strip()
            target = str(edge.get("target") or "").strip()
            if source in selected_nodes and target in selected_nodes:
                edge_ids.append(str(edge.get("id") or ""))
        return sorted({edge_id for edge_id in edge_ids if edge_id})

    trees: list[dict[str, Any]] = []
    tree_union_nodes: set[str] = set()

    matched_set = set(valid_matched)
    for root_id in roots:
        root_desc = descendants(root_id)
        if not root_desc:
            continue
        if not (root_desc & matched_set):
            continue

        tree_union_nodes.update(root_desc)
        trees.append(
            {
                "root_id": root_id,
                "node_ids": sorted(root_desc),
                "edge_ids": edge_ids_for_nodes(root_desc),
            }
        )

    subtrees: list[dict[str, Any]] = []
    subtree_union_nodes: set[str] = set()

    for node_id in valid_matched:
        subtree_nodes = descendants(node_id)
        if not subtree_nodes:
            continue
        subtree_union_nodes.update(subtree_nodes)
        subtrees.append(
            {
                "root_id": node_id,
                "node_ids": sorted(subtree_nodes),
                "edge_ids": edge_ids_for_nodes(subtree_nodes),
            }
        )

    highlight_nodes = set(valid_matched) | tree_union_nodes | subtree_union_nodes
    highlight_edges = edge_ids_for_nodes(highlight_nodes)

    return {
        "matched_node_ids": valid_matched,
        "tree_count": len(trees),
        "subtree_count": len(subtrees),
        "trees": trees,
        "subtrees": subtrees,
        "highlight": {
            "node_ids": sorted(highlight_nodes),
            "edge_ids": highlight_edges,
        },
    }


def _fingerprint_graph(graph: dict[str, Any]) -> str:
    nodes = sorted(
        str(node.get("id") or "").strip()
        for node in list(graph.get("nodes") or [])
        if str(node.get("id") or "").strip()
    )

    edge_entries: list[str] = []
    for edge in list(graph.get("edges") or []):
        source = str(edge.get("source") or edge.get("from") or "").strip()
        target = str(edge.get("target") or edge.get("to") or "").strip()
        if not source or not target:
            continue
        relation = str(edge.get("type") or edge.get("label") or "RELATED_TO").strip().upper()
        edge_entries.append(f"{source}>{relation}>{target}")

    edge_entries.sort()

    digest = hashlib.sha1()
    digest.update("|".join(nodes).encode("utf-8"))
    digest.update("||".join(edge_entries).encode("utf-8"))
    return digest.hexdigest()
