from __future__ import annotations

from ..models import TechniqueMatch


def compute_top1_accuracy(matches: list[TechniqueMatch], expected_technique: str) -> float:
    if not matches:
        return 0.0
    top = sorted(matches, key=lambda item: item.score, reverse=True)[0]
    return 1.0 if top.technique == expected_technique else 0.0
