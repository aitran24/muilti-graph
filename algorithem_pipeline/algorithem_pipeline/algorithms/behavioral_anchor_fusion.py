from __future__ import annotations

import json
import re
from collections import Counter, defaultdict, deque
from functools import lru_cache
from pathlib import Path
from time import perf_counter
from typing import Iterable

from .base import BaseMatcher
from ..models import GraphData, GraphEdge, GraphNode, TechniqueMatch


_TOKEN_RE = re.compile(r"[a-z0-9_./\\:-]+")
_TERM_TOKEN_RE = re.compile(r"[a-z0-9_.-]+")
_DEFAULT_SYSTEM_COMPONENTS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "reg.exe",
    "regedit.exe",
    "fodhelper.exe",
    "wmic.exe",
    "wmiprvse.exe",
    "schtasks.exe",
    "rundll32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "wevtutil.exe",
    "sc.exe",
    "net.exe",
    "net1.exe",
    "services.exe",
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "explorer.exe",
    "conhost.exe",
    "dllhost.exe",
}


def _normalize_component_name(value: object) -> str:
    text = str(value or "").strip().lower().strip("\"'")
    if not text:
        return ""
    text = text.split("\\")[-1].split("/")[-1].strip().strip("\"'")
    return text


def _component_aliases(value: object) -> set[str]:
    normalized = _normalize_component_name(value)
    if not normalized:
        return set()
    aliases = {normalized}
    if "." in normalized:
        aliases.add(normalized.rsplit(".", 1)[0])
    else:
        aliases.add(f"{normalized}.exe")
    return aliases


@lru_cache(maxsize=1)
def _load_system_component_index() -> set[str]:
    whitelist_path = Path(__file__).resolve().parents[3] / "analyzing" / "global_whitelist.json"
    payload: dict[str, object] = {}

    if whitelist_path.exists():
        try:
            payload = json.loads(whitelist_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}

    components: set[str] = set()

    for key in (
        "system_components",
        "lolbins",
        "low_priority_system_processes",
    ):
        values = payload.get(key) if isinstance(payload, dict) else None
        if not isinstance(values, list):
            continue
        for raw in values:
            components.update(_component_aliases(raw))

    if not components:
        for value in _DEFAULT_SYSTEM_COMPONENTS:
            components.update(_component_aliases(value))

    return {component for component in components if component}


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


def _term_tokens(value: str) -> list[str]:
    normalized = value.lower().replace("\\", " ").replace("/", " ").replace(":", " ")
    return [token for token in _TERM_TOKEN_RE.findall(normalized) if len(token) >= 2]


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

    slash_normalized = normalized.replace("\\", "/")
    slash_blob = blob.replace("\\", "/")
    if slash_normalized in slash_blob:
        return True

    significant = [token for token in _term_tokens(normalized) if len(token) >= 3]
    if not significant:
        return False
    blob_terms = set(_term_tokens(blob))
    return all(token in blob_terms or token in blob for token in significant[:6])


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


def _term_specificity(term: str) -> float:
    normalized = str(term or "").strip().lower()
    if not normalized:
        return 0.0

    tokens = _term_tokens(normalized)
    if not tokens:
        return 0.0

    if len(tokens) == 1:
        token = tokens[0]
        if token in {"powershell", "cmd", "reg", "sc", "net", "program"}:
            return 0.18
        if re.fullmatch(r"[0-9a-f]{4,8}", token):
            return 0.20
        if token.endswith(".exe"):
            return 0.45
        return 0.30

    weight = 0.55 + min(0.65, 0.10 * len(tokens))
    if any(token.endswith(".exe") for token in tokens):
        weight += 0.25
    if any(token in {"create", "query", "add", "delete", "save", "dump", "lsass", "wdigest"} for token in tokens):
        weight += 0.30
    if "\\" in normalized or "/" in normalized:
        weight += 0.15
    return min(1.5, weight)


def _term_concrete_behavior_weight(term: str) -> float:
    normalized = str(term or "").strip().lower()
    tokens = set(_term_tokens(normalized))
    if not tokens:
        return 0.0

    strong_indicators = {
        "mimikatz.exe",
        "procdump.exe",
        "procdump64.exe",
        "notprocdump.exe",
        "notprocdump64.exe",
        "outflank-dumpert.exe",
        "pypykatz",
        "lsass",
        "lsass.exe",
        "lsass.dmp",
        "wdigest",
        "uselogoncredential",
    }
    if tokens & strong_indicators:
        return 1.0

    action_tokens = {"create", "query", "add", "delete", "save", "dump", "cl", "clear"}
    tool_tokens = {"reg", "reg.exe", "schtasks", "schtasks.exe", "wevtutil", "wevtutil.exe", "ntdsutil", "ntdsutil.exe"}
    if ("schtasks" in tokens or "schtasks.exe" in tokens) and ("create" in tokens or "query" in tokens):
        return 1.0
    if ("wevtutil" in tokens or "wevtutil.exe" in tokens) and ("cl" in tokens or "clear" in tokens):
        return 1.0
    if ("reg" in tokens or "reg.exe" in tokens) and tokens & action_tokens:
        return 0.95 if len(tokens) >= 4 else 0.25
    if tokens & action_tokens and tokens & tool_tokens:
        return 1.0

    if "softwareinventorylogging" in tokens and ("reg" in tokens or "reg.exe" in tokens):
        return 0.9

    if tokens & action_tokens and len(tokens) >= 3:
        return 0.55

    return 0.0


class BehavioralAnchorFusionMatcher(BaseMatcher):
    name = "behavioral_anchor_fusion"

    def __init__(
        self,
        anchor_depth: int = 2,
        system_component_min_ratio: float = 0.50,
        max_matched_nodes: int = 160,
    ) -> None:
        self.anchor_depth = anchor_depth
        self.system_component_min_ratio = max(0.10, min(1.0, float(system_component_min_ratio or 0.50)))
        self.max_matched_nodes = max(20, int(max_matched_nodes or 20))
        self.system_component_index = _load_system_component_index()

    def match(self, target_graph: GraphData, pattern_graph: GraphData) -> TechniqueMatch:
        start = perf_counter()

        malicious_patterns = self._extract_patterns(pattern_graph)
        target_evidence = self._scan_pattern_terms(target_graph, malicious_patterns)
        pattern_anchor_ids = self._pattern_anchor_ids(pattern_graph, malicious_patterns)

        target_features = self._extract_features(target_graph, target_evidence["malicious_node_ids"])
        pattern_features = self._extract_features(pattern_graph, pattern_anchor_ids)

        object_score = _weighted_jaccard(target_features["object"], pattern_features["object"])
        relation_score = _weighted_jaccard(target_features["relation"], pattern_features["relation"])
        shape_score = _weighted_jaccard(target_features["shape"], pattern_features["shape"])
        anchor_score = _weighted_jaccard(target_features["anchor"], pattern_features["anchor"])
        system_relation_score = _weighted_jaccard(
            target_features["system_relation"],
            pattern_features["system_relation"],
        )

        pattern_system_components = set(pattern_features["system_components"])
        pattern_system_components.update(self._terms_system_components(malicious_patterns))
        target_system_components = set(target_features["system_components"])
        system_overlap = sorted(pattern_system_components & target_system_components)
        system_component_ratio = self._system_component_ratio(pattern_system_components, system_overlap)
        system_gate = self._system_gate_factor(system_component_ratio, bool(pattern_system_components))

        pattern_score = self._pattern_score(target_evidence, len(malicious_patterns))
        pattern_support = self._pattern_support(target_evidence)
        concrete_score = self._concrete_behavior_score(target_evidence)
        strongest_concrete = self._strongest_matched_concrete(target_evidence)
        supported_pattern_score = pattern_score * pattern_support

        fused_score = (
            0.60 * supported_pattern_score
            + 0.15 * anchor_score
            + 0.08 * object_score
            + 0.05 * relation_score
            + 0.04 * shape_score
            + 0.08 * system_relation_score
            + 0.10 * concrete_score
        )

        if malicious_patterns:
            fused_score *= 0.20 + (0.80 * (supported_pattern_score ** 2))
            if not target_evidence["malicious_terms"]:
                fused_score *= 0.02
            elif concrete_score <= 0.0:
                fused_score *= 0.20
            elif strongest_concrete < 0.50:
                fused_score *= 0.65
            elif strongest_concrete >= 0.90:
                fused_score += 0.06 * strongest_concrete

        fused_score *= system_gate

        score = max(0.0, min(1.0, fused_score))

        matched_node_ids = self._matched_node_ids(
            target_graph,
            target_evidence["malicious_node_ids"],
            target_features["node_scores"],
        )
        elapsed_ms = (perf_counter() - start) * 1000

        expected_system_preview = ", ".join(sorted(pattern_system_components)[:6]) or "-"
        overlap_system_preview = ", ".join(system_overlap[:6]) or "-"

        notes = (
            "Behavioral anchor fusion: malicious-pattern anchors + object tokens + "
            "edge semantics + graph shape. "
            f"patterns={len(target_evidence['malicious_terms'])}/{len(malicious_patterns)}, "
            f"pattern_score={pattern_score:.3f}, support={pattern_support:.3f}, "
            f"anchor={anchor_score:.3f}, object={object_score:.3f}, "
            f"relation={relation_score:.3f}, shape={shape_score:.3f}, "
            f"system_relation={system_relation_score:.3f}, "
            f"concrete={concrete_score:.3f}, "
            f"strong_concrete={strongest_concrete:.3f}, "
            f"system_ratio={system_component_ratio:.3f}, gate={system_gate:.3f}, "
            f"system_overlap={len(system_overlap)}/{len(pattern_system_components)}. "
            f"expected_system=[{expected_system_preview}] overlap_system=[{overlap_system_preview}]"
        )

        return TechniqueMatch(
            algorithm=self.name,
            technique=pattern_graph.technique,
            score=float(score),
            runtime_ms=elapsed_ms,
            matched_node_ids=matched_node_ids,
            notes=notes,
        )

    def _extract_patterns(self, graph: GraphData) -> list[str]:
        raw_patterns = graph.raw_payload.get("patterns", {})
        malicious: list[str] = []

        if isinstance(raw_patterns, dict):
            malicious = self._dedupe_terms(raw_patterns.get("malicious") or raw_patterns.get("patterns") or [])
        elif isinstance(raw_patterns, list):
            malicious = self._dedupe_terms(raw_patterns)

        return malicious

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
    ) -> dict[str, object]:
        node_blobs = {node_id: _node_blob(node) for node_id, node in graph.nodes.items()}
        malicious_terms: set[str] = set()
        malicious_node_ids: set[str] = set()

        for term in malicious_patterns:
            term_hit = False
            for node_id, blob in node_blobs.items():
                if _term_matches_blob(term, blob):
                    term_hit = True
                    malicious_node_ids.add(node_id)
            if term_hit:
                malicious_terms.add(term.lower())

        return {
            "all_malicious_patterns": malicious_patterns,
            "malicious_terms": malicious_terms,
            "malicious_node_ids": malicious_node_ids,
        }

    def _pattern_anchor_ids(self, graph: GraphData, malicious_patterns: list[str]) -> set[str]:
        matching = graph.raw_payload.get("matching", {})
        if isinstance(matching, dict):
            ids = matching.get("malicious_node_ids") or []
            if isinstance(ids, list):
                known_ids = {str(node_id) for node_id in ids if str(node_id) in graph.nodes}
                if known_ids:
                    return known_ids

        evidence = self._scan_pattern_terms(graph, malicious_patterns)
        return set(evidence["malicious_node_ids"])

    def _extract_features(self, graph: GraphData, anchor_ids: Iterable[str]) -> dict[str, object]:
        anchors = {node_id for node_id in anchor_ids if node_id in graph.nodes}
        neighborhoods = self._anchor_neighborhoods(graph, anchors)
        object_features: Counter[str] = Counter()
        relation_features: Counter[str] = Counter()
        system_relation_features: Counter[str] = Counter()
        shape_features: Counter[str] = Counter()
        anchor_features: Counter[str] = Counter()
        node_scores: Counter[str] = Counter()
        degree = self._degree_map(graph.edges)
        node_system_components: dict[str, set[str]] = {}
        context_system_components: set[str] = set()
        context_node_ids = anchors | neighborhoods if anchors else set(graph.nodes.keys())

        for node_id, node in graph.nodes.items():
            weight = 3 if node_id in anchors else 2 if node_id in neighborhoods else 1
            blob = _node_blob(node)
            system_components = self._node_system_components(node)
            node_system_components[node_id] = system_components
            if node_id in context_node_ids:
                context_system_components.update(system_components)

            object_features[f"type:{node.node_type}"] += weight
            object_features[f"group:{node.group.lower()}"] += weight
            shape_features[f"degree:{node.node_type}:{_bucket(degree[node_id])}"] += 1

            for component in sorted(system_components):
                object_features[f"sys:{component}"] += 4 * weight
                if node_id in anchors or node_id in neighborhoods:
                    anchor_features[f"sys:{component}"] += 4 * weight
                    node_scores[node_id] += 3

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
            edge_system_signatures: list[tuple[str, int]] = []

            source_system = node_system_components.get(edge.source, set())
            target_system = node_system_components.get(edge.target, set())
            if not near_anchor:
                source_system = set()
                target_system = set()

            if source_system and target_system:
                for source_comp in sorted(source_system)[:2]:
                    for target_comp in sorted(target_system)[:2]:
                        signature = f"sys_triple:{source_comp}>{edge_type}>{target_comp}"
                        delta = 3 * weight
                        system_relation_features[signature] += delta
                        edge_system_signatures.append((signature, delta))
            elif source_system:
                for source_comp in sorted(source_system)[:2]:
                    signature = f"sys_src:{source_comp}>{edge_type}>{target.node_type}"
                    delta = 2 * weight
                    system_relation_features[signature] += delta
                    edge_system_signatures.append((signature, delta))
            elif target_system:
                for target_comp in sorted(target_system)[:2]:
                    signature = f"sys_dst:{source.node_type}>{edge_type}>{target_comp}"
                    delta = 2 * weight
                    system_relation_features[signature] += delta
                    edge_system_signatures.append((signature, delta))

            if near_anchor:
                anchor_features[f"edge:{edge_type}"] += weight
                anchor_features[f"triple:{source.node_type}>{edge_type}>{target.node_type}"] += weight
                node_scores[edge.source] += 1
                node_scores[edge.target] += 1
                for signature, delta in edge_system_signatures:
                    anchor_features[signature] += delta

        shape_features[f"nodes:{_bucket(len(graph.nodes))}"] += 1
        shape_features[f"edges:{_bucket(len(graph.edges))}"] += 1
        shape_features[f"density:{self._density_bucket(graph)}"] += 1

        if not anchor_features:
            anchor_features.update(object_features)

        return {
            "object": object_features,
            "relation": relation_features,
            "system_relation": system_relation_features,
            "shape": shape_features,
            "anchor": anchor_features,
            "system_components": context_system_components,
            "node_scores": node_scores,
            "neighborhoods": neighborhoods,
        }

    def _terms_system_components(self, terms: Iterable[str]) -> set[str]:
        components: set[str] = set()
        for term in terms:
            for token in _term_tokens(str(term or "")):
                token_name = _normalize_component_name(token)
                if token_name in self.system_component_index:
                    components.add(token_name)
                elif "." not in token_name:
                    maybe_exe = f"{token_name}.exe"
                    if maybe_exe in self.system_component_index:
                        components.add(maybe_exe)
        return components

    def _node_system_components(self, node: GraphNode) -> set[str]:
        found: set[str] = set()
        candidates: list[object] = [
            node.label,
            node.id,
            node.properties.get("image_path"),
            node.properties.get("original_file_name"),
            node.properties.get("process_name"),
            node.properties.get("name"),
            node.properties.get("display_name"),
            node.properties.get("command_line"),
        ]

        for value in candidates:
            normalized = _normalize_component_name(value)
            if normalized in self.system_component_index:
                found.add(normalized)

            for token in _tokens(_normalize_text(value)):
                token_name = _normalize_component_name(token)
                if not token_name:
                    continue
                if token_name in self.system_component_index:
                    found.add(token_name)
                elif "." not in token_name:
                    maybe_exe = f"{token_name}.exe"
                    if maybe_exe in self.system_component_index:
                        found.add(maybe_exe)

        return found

    def _system_component_ratio(self, pattern_components: set[str], overlap_components: list[str]) -> float:
        if not pattern_components:
            return 1.0
        return len(overlap_components) / max(len(pattern_components), 1)

    def _system_gate_factor(self, ratio: float, has_pattern_system_components: bool) -> float:
        if not has_pattern_system_components:
            return 1.0

        bounded_ratio = max(0.0, min(1.0, ratio))
        if bounded_ratio >= self.system_component_min_ratio:
            return 1.0

        return max(0.05, bounded_ratio / max(self.system_component_min_ratio, 1e-6))

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
        matched_nodes = len(evidence["malicious_node_ids"])

        all_terms = list(evidence.get("all_malicious_patterns") or [])
        matched_terms = set(evidence["malicious_terms"])
        total_weight = sum(_term_specificity(term) for term in all_terms)
        matched_weight = sum(_term_specificity(term) for term in all_terms if term.lower() in matched_terms)
        coverage = matched_weight / total_weight if total_weight > 0 else 0.0
        locality = min(1.0, matched_nodes / max(total_malicious_patterns, 1))
        return float((0.78 * coverage) + (0.22 * locality))

    def _pattern_support(self, evidence: dict[str, object]) -> float:
        all_terms = list(evidence.get("all_malicious_patterns") or [])
        matched_terms = set(evidence["malicious_terms"])
        matched_weight = sum(_term_specificity(term) for term in all_terms if term.lower() in matched_terms)
        if matched_weight <= 0:
            return 0.0
        if matched_weight < 0.55:
            return 0.35
        if matched_weight < 1.15:
            return 0.70
        return 1.0

    def _concrete_behavior_score(self, evidence: dict[str, object]) -> float:
        all_terms = list(evidence.get("all_malicious_patterns") or [])
        matched_terms = set(evidence["malicious_terms"])
        if not all_terms or not matched_terms:
            return 0.0

        total_weight = sum(_term_concrete_behavior_weight(term) for term in all_terms)
        if total_weight <= 0:
            return 0.0

        matched_weight = sum(
            _term_concrete_behavior_weight(term)
            for term in all_terms
            if term.lower() in matched_terms
        )
        denominator = max(total_weight, 1.0)
        return max(0.0, min(1.0, matched_weight / denominator))

    def _strongest_matched_concrete(self, evidence: dict[str, object]) -> float:
        all_terms = list(evidence.get("all_malicious_patterns") or [])
        matched_terms = set(evidence["malicious_terms"])
        if not all_terms or not matched_terms:
            return 0.0
        return max(
            (_term_concrete_behavior_weight(term) for term in all_terms if term.lower() in matched_terms),
            default=0.0,
        )

    def _matched_node_ids(
        self,
        graph: GraphData,
        anchor_ids: Iterable[str],
        node_scores: Counter[str],
    ) -> list[str]:
        anchors = {node_id for node_id in anchor_ids if node_id in graph.nodes}
        if anchors:
            if node_scores:
                ranked_anchors = sorted(
                    anchors,
                    key=lambda node_id: node_scores.get(node_id, 0),
                    reverse=True,
                )
                return ranked_anchors[: self.max_matched_nodes]
            return sorted(anchors)[: self.max_matched_nodes]

        if not node_scores:
            return []
        return [node_id for node_id, _ in node_scores.most_common(self.max_matched_nodes)]