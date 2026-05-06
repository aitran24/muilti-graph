from __future__ import annotations

import json
import re
from collections import Counter, defaultdict, deque
from time import perf_counter
from typing import Iterable

from .base import BaseMatcher
from ..models import GraphData, GraphEdge, GraphNode, TechniqueMatch


_TOKEN_RE = re.compile(r"[a-z0-9_./\\:-]+")


def _normalize_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
        except TypeError:
            return str(value).lower()
    return str(value).lower()


def _tokens(value: str) -> list[str]:
    return [token for token in _TOKEN_RE.findall(value.lower()) if len(token) >= 2]


def _node_blob(node: GraphNode) -> str:
    parts = [node.id, node.label, node.node_type, node.group]
    for key, value in sorted(node.properties.items()):
        parts.append(key)
        parts.append(_normalize_text(value))
    return " ".join(parts).lower()


def _term_matches_blob(term: str, blob: str) -> bool:
    normalized = term.strip().lower()
    if not normalized:
        return False
    if normalized in blob:
        return True

    significant = [token for token in _tokens(normalized) if len(token) >= 3]
    if not significant:
        return False
    return all(token in blob for token in significant[:6])


def _weighted_jaccard(a: Counter[str], b: Counter[str]) -> float:
    keys = set(a.keys()) | set(b.keys())
    if not keys:
        return 0.0
    numerator = sum(min(a.get(key, 0.0), b.get(key, 0.0)) for key in keys)
    denominator = sum(max(a.get(key, 0.0), b.get(key, 0.0)) for key in keys)
    if denominator <= 0:
        return 0.0
    return float(numerator / denominator)


def _bucket(value: int) -> str:
    if value <= 0:
        return "0"
    if value == 1:
        return "1"
    if value <= 3:
        return "2-3"
    if value <= 7:
        return "4-7"
    return "8+"


class BehavioralAnchorFusionMatcher(BaseMatcher):
    name = "behavioral_anchor_fusion"

    def __init__(self, anchor_depth: int = 2) -> None:
        self.anchor_depth = anchor_depth

    def match(self, target_graph: GraphData, pattern_graph: GraphData) -> TechniqueMatch:
        start = perf_counter()

        malicious_patterns, whitelist_patterns = self._extract_patterns(pattern_graph)
        target_evidence = self._scan_pattern_terms(target_graph, malicious_patterns, whitelist_patterns)
        pattern_anchor_ids = self._pattern_anchor_ids(pattern_graph, malicious_patterns)

        target_features = self._extract_features(target_graph, target_evidence["malicious_node_ids"])
        pattern_features = self._extract_features(pattern_graph, pattern_anchor_ids)

        object_score = _weighted_jaccard(target_features["object"], pattern_features["object"])
        relation_score = _weighted_jaccard(target_features["relation"], pattern_features["relation"])
        shape_score = _weighted_jaccard(target_features["shape"], pattern_features["shape"])
        anchor_score = _weighted_jaccard(target_features["anchor"], pattern_features["anchor"])
        pattern_score = self._pattern_score(target_evidence, len(malicious_patterns))
        pattern_support = self._pattern_support(target_evidence)
        supported_pattern_score = pattern_score * pattern_support

        fused_score = (
            0.65 * supported_pattern_score
            + 0.15 * anchor_score
            + 0.08 * object_score
            + 0.07 * relation_score
            + 0.05 * shape_score
        )

        if malicious_patterns:
            fused_score *= 0.20 + (0.80 * (supported_pattern_score ** 2))

        whitelist_penalty = min(0.18, 0.03 * len(target_evidence["whitelist_terms"]))
        score = max(0.0, min(1.0, fused_score - whitelist_penalty))

        matched_node_ids = self._matched_node_ids(
            target_graph,
            target_evidence["malicious_node_ids"],
            target_features["node_scores"],
        )
        elapsed_ms = (perf_counter() - start) * 1000

        notes = (
            "Behavioral anchor fusion: malicious-pattern anchors + object tokens + "
            "edge semantics + graph shape. "
            f"patterns={len(target_evidence['malicious_terms'])}/{len(malicious_patterns)}, "
            f"pattern_score={pattern_score:.3f}, support={pattern_support:.3f}, "
            f"anchor={anchor_score:.3f}, object={object_score:.3f}, "
            f"relation={relation_score:.3f}, shape={shape_score:.3f}."
        )

        return TechniqueMatch(
            algorithm=self.name,
            technique=pattern_graph.technique,
            score=float(score),
            runtime_ms=elapsed_ms,
            matched_node_ids=matched_node_ids,
            notes=notes,
        )

    def _extract_patterns(self, graph: GraphData) -> tuple[list[str], list[str]]:
        raw_patterns = graph.raw_payload.get("patterns", {})
        malicious: list[str] = []
        whitelist: list[str] = []

        if isinstance(raw_patterns, dict):
            malicious = self._dedupe_terms(raw_patterns.get("malicious") or raw_patterns.get("patterns") or [])
            whitelist = self._dedupe_terms(raw_patterns.get("whitelist") or [])
        elif isinstance(raw_patterns, list):
            malicious = self._dedupe_terms(raw_patterns)

        return malicious, whitelist

    def _dedupe_terms(self, values: object) -> list[str]:
        if not isinstance(values, list):
            return []
        seen: set[str] = set()
        terms: list[str] = []
        for raw in values:
            term = str(raw or "").strip()
            key = term.lower()
            if not term or key in seen:
                continue
            seen.add(key)
            terms.append(term)
        return terms

    def _scan_pattern_terms(
        self,
        graph: GraphData,
        malicious_patterns: list[str],
        whitelist_patterns: list[str],
    ) -> dict[str, object]:
        node_blobs = {node_id: _node_blob(node) for node_id, node in graph.nodes.items()}
        malicious_terms: set[str] = set()
        whitelist_terms: set[str] = set()
        malicious_node_ids: set[str] = set()
        whitelist_node_ids: set[str] = set()

        for term in malicious_patterns:
            term_hit = False
            for node_id, blob in node_blobs.items():
                if _term_matches_blob(term, blob):
                    term_hit = True
                    malicious_node_ids.add(node_id)
            if term_hit:
                malicious_terms.add(term.lower())

        for term in whitelist_patterns:
            term_hit = False
            for node_id, blob in node_blobs.items():
                if _term_matches_blob(term, blob):
                    term_hit = True
                    whitelist_node_ids.add(node_id)
            if term_hit:
                whitelist_terms.add(term.lower())

        return {
            "malicious_terms": malicious_terms,
            "whitelist_terms": whitelist_terms,
            "malicious_node_ids": malicious_node_ids,
            "whitelist_node_ids": whitelist_node_ids,
        }

    def _pattern_anchor_ids(self, graph: GraphData, malicious_patterns: list[str]) -> set[str]:
        matching = graph.raw_payload.get("matching", {})
        if isinstance(matching, dict):
            ids = matching.get("malicious_node_ids") or []
            if isinstance(ids, list):
                known_ids = {str(node_id) for node_id in ids if str(node_id) in graph.nodes}
                if known_ids:
                    return known_ids

        evidence = self._scan_pattern_terms(graph, malicious_patterns, [])
        return set(evidence["malicious_node_ids"])

    def _extract_features(self, graph: GraphData, anchor_ids: Iterable[str]) -> dict[str, object]:
        anchors = {node_id for node_id in anchor_ids if node_id in graph.nodes}
        neighborhoods = self._anchor_neighborhoods(graph, anchors)
        object_features: Counter[str] = Counter()
        relation_features: Counter[str] = Counter()
        shape_features: Counter[str] = Counter()
        anchor_features: Counter[str] = Counter()
        node_scores: Counter[str] = Counter()
        degree = self._degree_map(graph.edges)

        for node_id, node in graph.nodes.items():
            weight = 3 if node_id in anchors else 2 if node_id in neighborhoods else 1
            blob = _node_blob(node)
            object_features[f"type:{node.node_type}"] += weight
            object_features[f"group:{node.group.lower()}"] += weight
            shape_features[f"degree:{node.node_type}:{_bucket(degree[node_id])}"] += 1
            for token in _tokens(blob):
                if len(token) <= 2:
                    continue
                object_features[f"tok:{token[:96]}"] += weight
                if node_id in anchors or node_id in neighborhoods:
                    anchor_features[f"tok:{token[:96]}"] += weight
                    node_scores[node_id] += 1

        for edge in graph.edges:
            source = graph.nodes.get(edge.source)
            target = graph.nodes.get(edge.target)
            if not source or not target:
                continue
            near_anchor = edge.source in neighborhoods or edge.target in neighborhoods
            weight = 2 if near_anchor else 1
            edge_type = edge.edge_type.strip().lower()
            relation_features[f"edge:{edge_type}"] += weight
            relation_features[f"triple:{source.node_type}>{edge_type}>{target.node_type}"] += weight
            if near_anchor:
                anchor_features[f"edge:{edge_type}"] += weight
                anchor_features[f"triple:{source.node_type}>{edge_type}>{target.node_type}"] += weight
                node_scores[edge.source] += 1
                node_scores[edge.target] += 1

        shape_features[f"nodes:{_bucket(len(graph.nodes))}"] += 1
        shape_features[f"edges:{_bucket(len(graph.edges))}"] += 1
        shape_features[f"density:{self._density_bucket(graph)}"] += 1

        if not anchor_features:
            anchor_features.update(object_features)

        return {
            "object": object_features,
            "relation": relation_features,
            "shape": shape_features,
            "anchor": anchor_features,
            "node_scores": node_scores,
            "neighborhoods": neighborhoods,
        }

    def _degree_map(self, edges: list[GraphEdge]) -> Counter[str]:
        degree: Counter[str] = Counter()
        for edge in edges:
            degree[edge.source] += 1
            degree[edge.target] += 1
        return degree

    def _density_bucket(self, graph: GraphData) -> str:
        density = len(graph.edges) / max(len(graph.nodes), 1)
        if density < 0.8:
            return "low"
        if density < 1.6:
            return "medium"
        return "high"

    def _anchor_neighborhoods(self, graph: GraphData, anchors: set[str]) -> set[str]:
        if not anchors:
            return set()

        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges:
            adjacency[edge.source].add(edge.target)
            adjacency[edge.target].add(edge.source)

        visited = set(anchors)
        queue = deque((node_id, 0) for node_id in anchors)
        while queue:
            node_id, depth = queue.popleft()
            if depth >= self.anchor_depth:
                continue
            for next_id in adjacency.get(node_id, set()):
                if next_id in visited or next_id not in graph.nodes:
                    continue
                visited.add(next_id)
                queue.append((next_id, depth + 1))
        return visited

    def _pattern_score(self, evidence: dict[str, object], total_malicious_patterns: int) -> float:
        if total_malicious_patterns <= 0:
            return 0.0
        matched_terms = len(evidence["malicious_terms"])
        matched_nodes = len(evidence["malicious_node_ids"])
        coverage = matched_terms / total_malicious_patterns
        locality = min(1.0, matched_nodes / max(total_malicious_patterns, 1))
        return float((0.78 * coverage) + (0.22 * locality))

    def _pattern_support(self, evidence: dict[str, object]) -> float:
        matched_terms = len(evidence["malicious_terms"])
        if matched_terms <= 0:
            return 0.0
        if matched_terms == 1:
            return 0.35
        if matched_terms == 2:
            return 0.70
        return 1.0

    def _matched_node_ids(
        self,
        graph: GraphData,
        anchor_ids: Iterable[str],
        node_scores: Counter[str],
    ) -> list[str]:
        anchors = {node_id for node_id in anchor_ids if node_id in graph.nodes}
        if anchors:
            highlighted = self._anchor_neighborhoods(graph, anchors)
            return sorted(highlighted)

        if not node_scores:
            return []
        return [node_id for node_id, _ in node_scores.most_common(30)]