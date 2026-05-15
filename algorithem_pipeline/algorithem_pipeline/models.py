from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str
    group: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    edge_type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphData:
    name: str
    technique: str
    nodes: dict[str, GraphNode]
    edges: list[GraphEdge]
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class TreeNode:
    id: str
    node_type: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    children: list["TreeNode"] = field(default_factory=list)


@dataclass
class TechniqueMatch:
    algorithm: str
    technique: str
    score: float
    runtime_ms: float
    matched_node_ids: list[str] = field(default_factory=list)
    malicious_node_ids: list[str] = field(default_factory=list)
    notes: str = ""
    core_node_ids: list[str] = field(default_factory=list)


@dataclass
class AlgorithmRunResult:
    algorithm: str
    runtime_ms: float
    matches: list[TechniqueMatch]
    accuracy: float
    top1_technique: str
    top1_score: float
    scheduler: dict[str, Any] = field(default_factory=dict)


@dataclass
class MatchRunResult:
    target_name: str
    target_technique: str
    algorithms: list[AlgorithmRunResult]
