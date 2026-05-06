from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class GraphDelta:
    added_nodes: list[dict[str, Any]] = field(default_factory=list)
    updated_nodes: list[dict[str, Any]] = field(default_factory=list)
    added_edges: list[dict[str, Any]] = field(default_factory=list)
    removed_edge_ids: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not (self.added_nodes or self.updated_nodes or self.added_edges or self.removed_edge_ids)

    def to_payload(self) -> dict[str, Any]:
        return {
            "added_nodes": self.added_nodes,
            "updated_nodes": self.updated_nodes,
            "added_edges": self.added_edges,
            "removed_edge_ids": self.removed_edge_ids,
            "stats": self.stats,
        }


@dataclass(slots=True)
class PollResult:
    delta: GraphDelta = field(default_factory=GraphDelta)
    events_seen: int = 0
    events_parsed: int = 0
    entities_mapped: int = 0
    triplets_created: int = 0
    last_record_id: int | None = None
    event_code_counts: dict[str, int] = field(default_factory=dict)

    def to_status(self) -> str:
        top_codes = sorted(
            self.event_code_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:5]
        top_codes_text = ",".join(f"{code}:{count}" for code, count in top_codes if code)

        return (
            f"seen={self.events_seen} parsed={self.events_parsed} "
            f"entities={self.entities_mapped} triplets={self.triplets_created}"
            + (f" event_ids={top_codes_text}" if top_codes_text else "")
        )


def merge_deltas(base: GraphDelta, new_delta: GraphDelta) -> GraphDelta:
    if new_delta.is_empty() and not new_delta.stats:
        if new_delta.stats:
            base.stats = new_delta.stats
        return base

    base.added_nodes.extend(new_delta.added_nodes)
    base.updated_nodes.extend(new_delta.updated_nodes)
    base.added_edges.extend(new_delta.added_edges)
    base.removed_edge_ids.extend(new_delta.removed_edge_ids)
    if new_delta.stats:
        base.stats = new_delta.stats
    return base
