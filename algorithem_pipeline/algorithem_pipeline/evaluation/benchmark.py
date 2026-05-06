from __future__ import annotations

from .metrics import compute_top1_accuracy
from ..models import AlgorithmRunResult, TechniqueMatch


def run_benchmark(
    algorithm_name: str,
    all_matches: list[TechniqueMatch],
    target_technique: str,
) -> AlgorithmRunResult:
    ordered = sorted(all_matches, key=lambda item: item.score, reverse=True)
    top = ordered[0] if ordered else None

    return AlgorithmRunResult(
        algorithm=algorithm_name,
        runtime_ms=sum(match.runtime_ms for match in all_matches),
        matches=ordered,
        accuracy=compute_top1_accuracy(ordered, target_technique),
        top1_technique=top.technique if top else "",
        top1_score=top.score if top else 0.0,
    )
