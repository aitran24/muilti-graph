from __future__ import annotations

from collections import Counter
from time import perf_counter

from .base import BaseMatcher
from .core_approximate import CoreApproximateMatcher
from ..io.tree_adapter import build_forest, collect_subtree_ids, graph_density
from ..models import GraphData, TechniqueMatch, TreeNode


def _tokenize(node: TreeNode) -> Counter[str]:
    counter: Counter[str] = Counter()
    counter[f"type:{node.node_type}"] += 1
    for token in node.label.strip().lower().split():
        if token:
            counter[f"label:{token}"] += 1
    for key in ("event_id", "command_line", "image_path", "key_path", "file_path", "destination_ip"):
        value = str(node.properties.get(key, "")).strip().lower()
        if value:
            counter[f"{key}:{value[:80]}"] += 1
    return counter


def _aggregate_tokens(root: TreeNode, depth: int = 2) -> Counter[str]:
    agg: Counter[str] = Counter()

    def walk(node: TreeNode, d: int) -> None:
        agg.update(_tokenize(node))
        if d <= 0:
            return
        for child in node.children:
            walk(child, d - 1)

    walk(root, depth)
    return agg


def _weighted_jaccard(a: Counter[str], b: Counter[str]) -> float:
    keys = set(a.keys()) | set(b.keys())
    if not keys:
        return 0.0
    num = sum(min(a.get(k, 0), b.get(k, 0)) for k in keys)
    den = sum(max(a.get(k, 0), b.get(k, 0)) for k in keys)
    if den <= 0:
        return 0.0
    return float(num / den)


class StructureAdaptiveMatcher(BaseMatcher):
    name = "structure_adaptive"

    def __init__(self) -> None:
        self._dense_fallback = CoreApproximateMatcher(threshold=0.58, missing_ratio_k=0.45)

    def match(self, target_graph: GraphData, pattern_graph: GraphData) -> TechniqueMatch:
        start = perf_counter()
        density = graph_density(target_graph)

        if density > 1.6:
            dense_result = self._dense_fallback.match(target_graph, pattern_graph)
            dense_result.algorithm = self.name
            dense_result.runtime_ms = (perf_counter() - start) * 1000
            dense_result.notes = (
                "Dense graph detected, fallback to approximate spanning-style matching."
            )
            return dense_result

        target_forest = build_forest(target_graph)
        pattern_forest = build_forest(pattern_graph)

        target_features: list[tuple[TreeNode, Counter[str]]] = []
        for root in target_forest:
            stack = [root]
            while stack:
                current = stack.pop()
                target_features.append((current, _aggregate_tokens(current, depth=2)))
                for child in current.children:
                    stack.append(child)

        matched_node_ids: list[str] = []
        matched = 0

        for pattern_root in pattern_forest:
            p_tokens = _aggregate_tokens(pattern_root, depth=2)
            best_score = 0.0
            best_root: TreeNode | None = None

            for candidate, candidate_tokens in target_features:
                score = _weighted_jaccard(p_tokens, candidate_tokens)
                if score > best_score:
                    best_score = score
                    best_root = candidate

            if best_root and best_score >= 0.35:
                matched += 1
                matched_node_ids.extend(collect_subtree_ids(best_root))

        score = matched / max(len(pattern_forest), 1)
        elapsed_ms = (perf_counter() - start) * 1000

        return TechniqueMatch(
            algorithm=self.name,
            technique=pattern_graph.technique,
            score=float(score),
            runtime_ms=elapsed_ms,
            matched_node_ids=sorted(set(matched_node_ids)),
            notes="Sparse-graph adaptive matcher with weighted token context.",
        )
