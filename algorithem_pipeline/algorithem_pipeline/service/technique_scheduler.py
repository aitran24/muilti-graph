from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from typing import Iterable

from ..models import TechniqueMatch


@dataclass(slots=True)
class TechniqueSelection:
    run_index: int
    candidates: list[str]
    catalog_count: int
    low_queue_size: int
    cooldown_size: int


@dataclass(slots=True)
class TechniqueSchedulerStatus:
    run_index: int
    catalog_count: int
    candidates_evaluated: int
    cached_match_count: int
    low_queue_size: int
    cooldown_size: int
    warning_cooldown_hits: int
    low_queue_batch_size: int
    warning_threshold: float
    low_score_threshold: float
    warning_streak_runs: int
    cooldown_runs: int

    def to_payload(self) -> dict[str, int | float]:
        return {
            "run_index": self.run_index,
            "catalog_count": self.catalog_count,
            "candidates_evaluated": self.candidates_evaluated,
            "cached_match_count": self.cached_match_count,
            "low_queue_size": self.low_queue_size,
            "cooldown_size": self.cooldown_size,
            "warning_cooldown_hits": self.warning_cooldown_hits,
            "low_queue_batch_size": self.low_queue_batch_size,
            "warning_threshold": self.warning_threshold,
            "low_score_threshold": self.low_score_threshold,
            "warning_streak_runs": self.warning_streak_runs,
            "cooldown_runs": self.cooldown_runs,
        }


@dataclass(slots=True)
class _TechniqueState:
    warning_streak: int = 0
    cooldown_remaining: int = 0


class TechniqueScheduler:
    """Reduce repeated full-catalog matching with cooldown and low-score rotation."""

    def __init__(
        self,
        *,
        low_score_threshold: float = 0.1,
        warning_threshold: float = 0.2,
        warning_streak_runs: int = 3,
        cooldown_runs: int = 20,
        low_queue_batch_size: int = 10,
    ) -> None:
        self.low_score_threshold = float(low_score_threshold)
        self.warning_threshold = float(warning_threshold)
        self.warning_streak_runs = max(1, int(warning_streak_runs))
        self.cooldown_runs = max(1, int(cooldown_runs))
        self.low_queue_batch_size = max(1, int(low_queue_batch_size))

        self.run_index = 0
        self._states: dict[str, _TechniqueState] = {}
        self._low_queue: deque[str] = deque()
        self._low_set: set[str] = set()
        self._last_matches: dict[str, TechniqueMatch] = {}
        self._last_selection = TechniqueSelection(
            run_index=0,
            candidates=[],
            catalog_count=0,
            low_queue_size=0,
            cooldown_size=0,
        )

    def select(self, catalog_techniques: Iterable[str]) -> TechniqueSelection:
        catalog = [str(item).strip() for item in catalog_techniques if str(item).strip()]
        catalog_set = set(catalog)

        self.run_index += 1
        self._prune_missing(catalog_set)

        cooldown_techniques: set[str] = set()
        for technique in catalog:
            state = self._states.setdefault(technique, _TechniqueState())
            if state.cooldown_remaining > 0:
                state.cooldown_remaining -= 1
                cooldown_techniques.add(technique)

        selected: list[str] = []
        selected_set: set[str] = set()

        for technique in catalog:
            if technique in cooldown_techniques or technique in self._low_set:
                continue
            selected.append(technique)
            selected_set.add(technique)

        low_batch = self._next_low_queue_batch(catalog_set, cooldown_techniques)
        for technique in low_batch:
            if technique in selected_set:
                continue
            selected.append(technique)
            selected_set.add(technique)

        selection = TechniqueSelection(
            run_index=self.run_index,
            candidates=selected,
            catalog_count=len(catalog),
            low_queue_size=len(self._low_queue),
            cooldown_size=sum(
                1 for state in self._states.values() if state.cooldown_remaining > 0
            ),
        )
        self._last_selection = selection
        return selection

    def update(self, matches: Iterable[TechniqueMatch]) -> TechniqueSchedulerStatus:
        current_matches: dict[str, TechniqueMatch] = {}
        warning_cooldown_hits = 0

        for match in matches:
            technique = str(match.technique or "").strip()
            if not technique:
                continue

            current_matches[technique] = match
            self._last_matches[technique] = match
            state = self._states.setdefault(technique, _TechniqueState())
            score = float(match.score or 0.0)

            if score >= self.warning_threshold:
                state.warning_streak += 1
                self._remove_low(technique)
                if state.warning_streak >= self.warning_streak_runs:
                    state.warning_streak = 0
                    state.cooldown_remaining = self.cooldown_runs
                    warning_cooldown_hits += 1
                continue

            state.warning_streak = 0
            if score < self.low_score_threshold:
                self._add_low(technique)
            else:
                self._remove_low(technique)

        return TechniqueSchedulerStatus(
            run_index=self._last_selection.run_index,
            catalog_count=self._last_selection.catalog_count,
            candidates_evaluated=len(current_matches),
            cached_match_count=len(self._last_matches),
            low_queue_size=len(self._low_queue),
            cooldown_size=sum(
                1 for state in self._states.values() if state.cooldown_remaining > 0
            ),
            warning_cooldown_hits=warning_cooldown_hits,
            low_queue_batch_size=self.low_queue_batch_size,
            warning_threshold=self.warning_threshold,
            low_score_threshold=self.low_score_threshold,
            warning_streak_runs=self.warning_streak_runs,
            cooldown_runs=self.cooldown_runs,
        )

    def materialize_matches(self, current_matches: Iterable[TechniqueMatch]) -> list[TechniqueMatch]:
        current_by_technique: dict[str, TechniqueMatch] = {}
        for match in current_matches:
            technique = str(match.technique or "").strip()
            if technique:
                current_by_technique[technique] = match

        materialized = list(current_by_technique.values())
        for technique, match in self._last_matches.items():
            if technique in current_by_technique:
                continue
            materialized.append(replace(match, runtime_ms=0.0))
        return materialized

    def _next_low_queue_batch(
        self,
        catalog_set: set[str],
        cooldown_techniques: set[str],
    ) -> list[str]:
        batch: list[str] = []
        attempts = len(self._low_queue)

        for _ in range(attempts):
            if len(batch) >= self.low_queue_batch_size or not self._low_queue:
                break

            technique = self._low_queue.popleft()
            if technique not in catalog_set:
                self._low_set.discard(technique)
                continue

            self._low_queue.append(technique)
            if technique in cooldown_techniques:
                continue

            batch.append(technique)

        return batch

    def _add_low(self, technique: str) -> None:
        if technique in self._low_set:
            return
        self._low_set.add(technique)
        self._low_queue.append(technique)

    def _remove_low(self, technique: str) -> None:
        if technique not in self._low_set:
            return
        self._low_set.discard(technique)
        self._low_queue = deque(item for item in self._low_queue if item != technique)

    def _prune_missing(self, catalog_set: set[str]) -> None:
        missing = set(self._states) - catalog_set
        for technique in missing:
            self._states.pop(technique, None)
            self._last_matches.pop(technique, None)
            self._low_set.discard(technique)

        if missing:
            self._low_queue = deque(item for item in self._low_queue if item in catalog_set)
