from __future__ import annotations

from functools import lru_cache
from itertools import permutations
from time import perf_counter

from .base import BaseMatcher
from ..io.tree_adapter import build_forest, collect_subtree_ids
from ..models import GraphData, TechniqueMatch, TreeNode


def _node_cost(a: TreeNode, b: TreeNode) -> float:
    type_cost = 0.0 if a.node_type == b.node_type else 0.6
    label_cost = 0.0 if a.label.strip().lower() == b.label.strip().lower() else 0.4
    return type_cost + label_cost


def _tree_size(node: TreeNode) -> int:
    return 1 + sum(_tree_size(child) for child in node.children)


def _child_match_cost(a_children: list[TreeNode], b_children: list[TreeNode]) -> float:
    if not a_children and not b_children:
        return 0.0
    if not a_children:
        return float(len(b_children))
    if not b_children:
        return float(len(a_children))

    # Exact assignment is expensive; use exhaustive search only for small fan-out.
    if len(a_children) <= 4 and len(b_children) <= 4:
        small = a_children
        large = b_children
        swapped = False
        if len(a_children) > len(b_children):
            small = b_children
            large = a_children
            swapped = True

        best_cost = float("inf")
        for pick in permutations(range(len(large)), len(small)):
            cost = 0.0
            for i, j in enumerate(pick):
                left = small[i]
                right = large[j]
                pair_cost = _edit_distance(left, right) if not swapped else _edit_distance(right, left)
                cost += pair_cost
            cost += abs(len(a_children) - len(b_children))
            best_cost = min(best_cost, cost)
        return best_cost

    # Greedy fallback for higher degree nodes.
    used: set[int] = set()
    cost = 0.0
    for child_a in a_children:
        best_idx = -1
        best_cost = float("inf")
        for idx, child_b in enumerate(b_children):
            if idx in used:
                continue
            pair_cost = _edit_distance(child_a, child_b)
            if pair_cost < best_cost:
                best_cost = pair_cost
                best_idx = idx
        if best_idx >= 0:
            used.add(best_idx)
            cost += best_cost
        else:
            cost += 1.0

    cost += max(0, len(b_children) - len(used))
    return cost


@lru_cache(maxsize=4096)
def _edit_distance_cached(a_sig: tuple, b_sig: tuple) -> float:
    a_node, b_node = a_sig[-1], b_sig[-1]
    return float(abs(hash(a_node) - hash(b_node)) % 3)


def _edit_distance(a: TreeNode, b: TreeNode) -> float:
    # Cached placeholder not used directly for recursion because TreeNode is mutable.
    own = _node_cost(a, b)
    child_cost = _child_match_cost(a.children, b.children)
    return own + child_cost


class CoreApproximateMatcher(BaseMatcher):
    name = "core_approximate"

    def __init__(self, threshold: float = 0.65, missing_ratio_k: float = 0.35):
        self.threshold = threshold
        self.missing_ratio_k = missing_ratio_k

    def _similarity(self, target_subtree: TreeNode, pattern_subtree: TreeNode) -> tuple[float, float]:
        dist = _edit_distance(target_subtree, pattern_subtree)
        norm = max(_tree_size(target_subtree), _tree_size(pattern_subtree), 1)
        similarity = max(0.0, 1.0 - (dist / norm))
        missing_ratio = min(1.0, dist / max(_tree_size(pattern_subtree), 1))
        return similarity, missing_ratio

    def match(self, target_graph: GraphData, pattern_graph: GraphData) -> TechniqueMatch:
        start = perf_counter()

        target_forest = build_forest(target_graph)
        pattern_forest = build_forest(pattern_graph)

        target_candidates: list[TreeNode] = []

        def collect(node: TreeNode) -> None:
            target_candidates.append(node)
            for child in node.children:
                collect(child)

        for root in target_forest:
            collect(root)

        matched_node_ids: list[str] = []
        matched_roots = 0

        for pattern_root in pattern_forest:
            best_similarity = 0.0
            best_missing = 1.0
            best_target: TreeNode | None = None

            for candidate in target_candidates:
                similarity, missing_ratio = self._similarity(candidate, pattern_root)
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_missing = missing_ratio
                    best_target = candidate

            if best_target and (
                best_similarity >= self.threshold or best_missing <= self.missing_ratio_k
            ):
                matched_roots += 1
                matched_node_ids.extend(collect_subtree_ids(best_target))

        score = matched_roots / max(len(pattern_forest), 1)
        elapsed_ms = (perf_counter() - start) * 1000

        return TechniqueMatch(
            algorithm=self.name,
            technique=pattern_graph.technique,
            score=float(score),
            runtime_ms=elapsed_ms,
            matched_node_ids=sorted(set(matched_node_ids)),
            notes=(
                "Approximate tree matching with edit-distance style scoring, "
                f"theta={self.threshold}, k={self.missing_ratio_k}."
            ),
        )
