from __future__ import annotations

from time import perf_counter

from .base import BaseMatcher
from ..io.tree_adapter import build_forest, collect_subtree_ids
from ..models import GraphData, TechniqueMatch, TreeNode


def _node_signature(node: TreeNode) -> str:
    return f"{node.node_type}|{node.label.strip().lower()}"


def _canonical_hash(node: TreeNode) -> str:
    child_hashes = sorted(_canonical_hash(child) for child in node.children)
    return f"({_node_signature(node)}:{'|'.join(child_hashes)})"


class BaselineExactMatcher(BaseMatcher):
    name = "baseline_exact"

    def match(self, target_graph: GraphData, pattern_graph: GraphData) -> TechniqueMatch:
        start = perf_counter()

        target_forest = build_forest(target_graph)
        pattern_forest = build_forest(pattern_graph)

        target_hash_to_ids: dict[str, list[list[str]]] = {}

        def index_target(node: TreeNode) -> None:
            key = _canonical_hash(node)
            target_hash_to_ids.setdefault(key, []).append(collect_subtree_ids(node))
            for child in node.children:
                index_target(child)

        for root in target_forest:
            index_target(root)

        total_roots = max(len(pattern_forest), 1)
        matched_roots = 0
        matched_node_ids: list[str] = []

        for pattern_root in pattern_forest:
            key = _canonical_hash(pattern_root)
            hit_list = target_hash_to_ids.get(key, [])
            if hit_list:
                matched_roots += 1
                matched_node_ids.extend(hit_list[0])

        score = matched_roots / total_roots
        elapsed_ms = (perf_counter() - start) * 1000

        return TechniqueMatch(
            algorithm=self.name,
            technique=pattern_graph.technique,
            score=float(score),
            runtime_ms=elapsed_ms,
            matched_node_ids=sorted(set(matched_node_ids)),
            notes="Exact subtree isomorphism via canonical hash.",
        )
