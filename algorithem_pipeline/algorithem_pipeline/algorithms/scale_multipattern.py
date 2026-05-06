from __future__ import annotations

from collections import defaultdict
from time import perf_counter

from .base import BaseMatcher
from ..io.tree_adapter import build_forest, collect_subtree_ids
from ..models import GraphData, TechniqueMatch, TreeNode


def _compact_signature(node: TreeNode) -> str:
    return f"{node.node_type}:{node.label.strip().lower()}"


def _hash_subtree(node: TreeNode, cache: dict[str, str], hit_nodes: dict[str, list[str]]) -> str:
    if node.id in cache:
        return cache[node.id]

    child_hashes = sorted(_hash_subtree(child, cache, hit_nodes) for child in node.children)
    value = f"[{_compact_signature(node)}|{'|'.join(child_hashes)}]"
    cache[node.id] = value
    hit_nodes[value] = collect_subtree_ids(node)
    return value


class ScaleMultiPatternMatcher(BaseMatcher):
    name = "scale_multipattern"

    def __init__(self) -> None:
        self._pattern_index: dict[str, set[str]] = defaultdict(set)

    def _compile_pattern(self, pattern_graph: GraphData) -> set[str]:
        pattern_hashes: set[str] = set()
        forest = build_forest(pattern_graph)

        cache: dict[str, str] = {}
        throwaway: dict[str, list[str]] = {}
        for root in forest:
            stack = [root]
            while stack:
                current = stack.pop()
                pattern_hashes.add(_hash_subtree(current, cache, throwaway))
                for child in current.children:
                    stack.append(child)
        return pattern_hashes

    def match(self, target_graph: GraphData, pattern_graph: GraphData) -> TechniqueMatch:
        start = perf_counter()

        if pattern_graph.technique not in self._pattern_index:
            self._pattern_index[pattern_graph.technique] = self._compile_pattern(pattern_graph)

        target_forest = build_forest(target_graph)
        cache: dict[str, str] = {}
        target_hash_to_ids: dict[str, list[str]] = {}

        for root in target_forest:
            stack = [root]
            while stack:
                current = stack.pop()
                _hash_subtree(current, cache, target_hash_to_ids)
                for child in current.children:
                    stack.append(child)

        pattern_hashes = self._pattern_index[pattern_graph.technique]
        hit_hashes = pattern_hashes.intersection(target_hash_to_ids.keys())

        matched_node_ids: list[str] = []
        for hit_hash in hit_hashes:
            matched_node_ids.extend(target_hash_to_ids[hit_hash])

        score = len(hit_hashes) / max(len(pattern_hashes), 1)
        elapsed_ms = (perf_counter() - start) * 1000

        return TechniqueMatch(
            algorithm=self.name,
            technique=pattern_graph.technique,
            score=float(score),
            runtime_ms=elapsed_ms,
            matched_node_ids=sorted(set(matched_node_ids)),
            notes="Multi-pattern subtree hashing in one target traversal.",
        )
