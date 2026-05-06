from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import GraphData, TechniqueMatch


class BaseMatcher(ABC):
    name: str = "base"

    @abstractmethod
    def match(self, target_graph: GraphData, pattern_graph: GraphData) -> TechniqueMatch:
        raise NotImplementedError
