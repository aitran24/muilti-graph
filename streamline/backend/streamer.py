from __future__ import annotations

from streamline.backend.config import StreamlineConfig
from streamline.backend.eventlog_source import EventRecord, SysmonEventLogSource
from streamline.backend.graph_state import StreamGraphState
from streamline.backend.imports_bridge import (
    SysmonLogParser,
    SysmonTripletCreator,
    clear_all_globals,
)
from streamline.backend.models import GraphDelta, PollResult, merge_deltas


class LiveStreamPipeline:
    """Transforms new Sysmon EventLog records into incremental graph updates."""

    def __init__(self, config: StreamlineConfig) -> None:
        self._config = config
        self._source = SysmonEventLogSource(channel=config.channel)
        self._parser = SysmonLogParser()
        self._triplet_creator = SysmonTripletCreator(graph_manager=None)
        self._graph = StreamGraphState(technique_name=config.technique_name)
        self._last_record_id: int | None = None

    @property
    def last_record_id(self) -> int | None:
        return self._last_record_id

    def snapshot(self) -> dict:
        return self._graph.snapshot()

    def clear_event_log(self) -> None:
        self._source.clear_channel()
        self._last_record_id = self._source.read_latest_record_id()

    def _process_records(self, records: list[EventRecord]) -> PollResult:
        result = PollResult(delta=GraphDelta())
        event_code_counts: dict[str, int] = {}

        for record in records:
            result.events_seen += 1
            parsed_entries = self._parser.parse_from_rawlog([record.xml]) or []
            result.events_parsed += len(parsed_entries)

            for entry in parsed_entries:
                event_code = str(entry.get("EventCode") or "").strip()
                if event_code:
                    event_code_counts[event_code] = event_code_counts.get(event_code, 0) + 1

                entity = self._parser.map_entity(entry)
                if not entity:
                    continue
                result.entities_mapped += 1

                triplet = self._triplet_creator.create_triplet(entity)
                if not triplet:
                    continue
                result.triplets_created += 1

                event_delta = self._graph.apply_triplet(triplet)
                result.delta = merge_deltas(result.delta, event_delta)

        result.delta.stats = self._graph.stats()
        result.last_record_id = SysmonEventLogSource.max_record_id(records)
        result.event_code_counts = event_code_counts
        return result

    def bootstrap(self) -> PollResult:
        clear_all_globals()

        if self._last_record_id is not None:
            return PollResult(delta=GraphDelta(stats=self._graph.stats()), last_record_id=self._last_record_id)

        if self._config.bootstrap_count <= 0:
            self._last_record_id = self._source.read_latest_record_id()
            return PollResult(delta=GraphDelta(stats=self._graph.stats()), last_record_id=self._last_record_id)

        records = self._source.read_recent_events(self._config.bootstrap_count)
        result = self._process_records(records)

        if result.last_record_id is not None:
            self._last_record_id = result.last_record_id
        else:
            self._last_record_id = self._source.read_latest_record_id()
        return result

    def poll_once(self) -> PollResult:
        if self._last_record_id is None:
            self._last_record_id = self._source.read_latest_record_id()
            return PollResult(delta=GraphDelta(stats=self._graph.stats()), last_record_id=self._last_record_id)

        aggregate = PollResult(delta=GraphDelta(stats=self._graph.stats()), last_record_id=self._last_record_id)
        batch_size = max(1, int(self._config.batch_size or 1))
        max_batches = max(1, int(self._config.poll_max_batches or 1))

        for _ in range(max_batches):
            records = self._source.read_events_after(
                record_id=self._last_record_id,
                max_count=batch_size,
            )
            if not records:
                break

            batch_result = self._process_records(records)
            aggregate.batches_read += 1
            aggregate.events_seen += batch_result.events_seen
            aggregate.events_parsed += batch_result.events_parsed
            aggregate.entities_mapped += batch_result.entities_mapped
            aggregate.triplets_created += batch_result.triplets_created
            aggregate.delta = merge_deltas(aggregate.delta, batch_result.delta)

            for event_code, count in batch_result.event_code_counts.items():
                aggregate.event_code_counts[event_code] = aggregate.event_code_counts.get(event_code, 0) + count

            if batch_result.last_record_id is not None:
                self._last_record_id = batch_result.last_record_id
            else:
                self._last_record_id = max(self._last_record_id, SysmonEventLogSource.max_record_id(records) or 0)

            aggregate.last_record_id = self._last_record_id
            if len(records) < batch_size:
                break

        aggregate.delta.stats = self._graph.stats()
        aggregate.last_record_id = self._last_record_id
        return aggregate
