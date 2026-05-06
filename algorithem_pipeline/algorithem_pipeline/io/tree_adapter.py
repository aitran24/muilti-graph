from __future__ import annotations

from collections import defaultdict

from ..models import GraphData, TreeNode


def _is_root_edge(edge_type: str) -> bool:
    return edge_type.strip().upper() == "HAS_ROOT"


def build_forest(graph: GraphData) -> list[TreeNode]:
    children_map: dict[str, set[str]] = defaultdict(set)
    incoming_count: dict[str, int] = defaultdict(int)
    explicit_roots: list[str] = []

    for edge in graph.edges:
        if _is_root_edge(edge.edge_type):
            explicit_roots.append(edge.target)
            continue
        children_map[edge.source].add(edge.target)
        incoming_count[edge.target] += 1

    roots = [node_id for node_id in explicit_roots if node_id in graph.nodes]
    if not roots:
        roots = [node_id for node_id in graph.nodes if incoming_count.get(node_id, 0) == 0]

    def build_node(node_id: str, path: set[str]) -> TreeNode:
        node = graph.nodes[node_id]
        tree = TreeNode(
            id=node.id,
            node_type=node.node_type,
            label=node.label,
            properties=node.properties,
            children=[],
        )
        if node_id in path:
            return tree

        next_path = set(path)
        next_path.add(node_id)

        for child_id in sorted(children_map.get(node_id, set())):
            if child_id not in graph.nodes:
                continue
            child_tree = build_node(child_id, next_path)
            tree.children.append(child_tree)
        return tree

    forest: list[TreeNode] = []
    for root_id in roots:
        forest.append(build_node(root_id, set()))
    return forest


def collect_subtree_ids(root: TreeNode) -> list[str]:
    ids: list[str] = []

    def walk(node: TreeNode) -> None:
        ids.append(node.id)
        for child in node.children:
            walk(child)

    walk(root)
    return ids


def graph_density(graph: GraphData) -> float:
    node_count = max(len(graph.nodes), 1)
    relation_edges = sum(1 for edge in graph.edges if not _is_root_edge(edge.edge_type))
    return relation_edges / node_count
