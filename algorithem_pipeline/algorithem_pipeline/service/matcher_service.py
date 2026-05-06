from __future__ import annotations

import sys
from pathlib import Path

from ..algorithms import (
    BaselineExactMatcher,
    BehavioralAnchorFusionMatcher,
    CoreApproximateMatcher,
    ScaleMultiPatternMatcher,
    StructureAdaptiveMatcher,
)
from ..config import PipelineConfig
from ..evaluation.benchmark import run_benchmark
from ..io.graph_loader import (
    load_graph_payload,
    load_pattern_catalog,
)
from ..models import MatchRunResult


class MatcherService:
    def __init__(self, repo_root: Path) -> None:
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))

        from inspect_log_gui.backend.pipeline import TechniqueGraphPipeline

        self.config = PipelineConfig.from_repo_root(repo_root)
        self.catalog = load_pattern_catalog(self.config.pattern_dir)
        self.target_pipeline = TechniqueGraphPipeline(dataset_folder=self.config.dataset_dir)
        self.algorithms = {
            "baseline_exact": BaselineExactMatcher(),
            "core_approximate": CoreApproximateMatcher(),
            "scale_multipattern": ScaleMultiPatternMatcher(),
            "structure_adaptive": StructureAdaptiveMatcher(),
            "behavioral_anchor_fusion": BehavioralAnchorFusionMatcher(),
        }

    def list_targets(self) -> list[str]:
        return self.target_pipeline.list_techniques()

    def list_techniques(self) -> list[str]:
        return sorted(self.catalog.keys())

    def load_target_graph(self, technique_name: str):
        graph_payload = self.target_pipeline.build_graph(technique_name)
        return load_graph_payload(graph_payload, name=f"{technique_name}.json")

    def run(
        self,
        target_name: str,
        algorithm_names: list[str] | None = None,
        top_k: int = 20,
    ) -> MatchRunResult:
        target_graph = self.load_target_graph(target_name)
        selected = algorithm_names or list(self.algorithms.keys())

        algorithm_results = []
        for algorithm_name in selected:
            matcher = self.algorithms.get(algorithm_name)
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
            benchmark.matches = benchmark.matches[:top_k]
            algorithm_results.append(benchmark)

        return MatchRunResult(
            target_name=target_graph.name,
            target_technique=target_graph.technique,
            algorithms=algorithm_results,
        )
