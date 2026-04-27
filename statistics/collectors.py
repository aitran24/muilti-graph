from __future__ import annotations

import gc
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from class_define.graph_definition import resolve_graph_entity_type
from globals.global_object import clear_all_globals
from graph_db.neo4j_manager import Neo4jGraphManager
from log_parsers.sysmon_parser import SysmonLogParser
from triplet_creator.triplet_creator import SysmonTripletCreator

from statistics.common import SUPPORTED_LOG_SUFFIXES, sort_counter


@dataclass
class TechniqueSummary:
    technique_name: str
    log_file_count: int
    total_logs: int
    mapped_entities: int
    skipped_entities: int
    skipped_triplets: int
    relationship_count: int
    unique_node_count: int
    root_count: int


class CurrentPipelineStatsCollector:
    def __init__(self) -> None:
        self._parser = SysmonLogParser()
        self._triplet_creator = SysmonTripletCreator(graph_manager=None)

    @staticmethod
    def _find_sysmon_logs(folder: Path) -> list[Path]:
        return sorted(
            file_path
            for file_path in folder.rglob("*")
            if file_path.is_file()
            and "sysmon" in file_path.name.lower()
            and file_path.suffix.lower() in SUPPORTED_LOG_SUFFIXES
        )

    @staticmethod
    def _cleanup() -> None:
        clear_all_globals()
        gc.collect()

    def collect(self, dataset_folder: Path) -> dict[str, Any]:
        if not dataset_folder.exists() or not dataset_folder.is_dir():
            raise FileNotFoundError(f"Dataset folder does not exist: {dataset_folder}")

        total_log_files = 0
        total_logs = 0
        total_mapped_entities = 0
        total_skipped_entities = 0
        total_skipped_triplets = 0

        unique_node_ids: set[str] = set()
        subject_ids_all: set[str] = set()
        object_ids_all: set[str] = set()

        node_type_counter: Counter[str] = Counter()
        relationship_type_counter: Counter[str] = Counter()
        event_id_counter: Counter[str] = Counter()

        technique_relation_matrix: defaultdict[str, Counter[str]] = defaultdict(Counter)
        technique_summaries: list[TechniqueSummary] = []

        technique_folders = sorted(path for path in dataset_folder.iterdir() if path.is_dir())
        for technique_folder in technique_folders:
            technique_name = technique_folder.name
            sysmon_logs = self._find_sysmon_logs(technique_folder)

            if not sysmon_logs:
                self._cleanup()
                continue

            technique_log_files = 0
            technique_total_logs = 0
            technique_mapped_entities = 0
            technique_skipped_entities = 0
            technique_skipped_triplets = 0
            technique_relationships = 0
            technique_unique_nodes: set[str] = set()
            technique_subject_ids: set[str] = set()
            technique_object_ids: set[str] = set()

            try:
                for log_file in sysmon_logs:
                    total_log_files += 1
                    technique_log_files += 1

                    log_entries = self._parser.parse_from_file(str(log_file))
                    total_logs += len(log_entries)
                    technique_total_logs += len(log_entries)

                    for log_entry in log_entries:
                        entity = self._parser.map_entity(log_entry)
                        if not entity:
                            total_skipped_entities += 1
                            technique_skipped_entities += 1
                            continue

                        total_mapped_entities += 1
                        technique_mapped_entities += 1

                        triplet = self._triplet_creator.create_triplet(entity)
                        if not triplet:
                            total_skipped_triplets += 1
                            technique_skipped_triplets += 1
                            continue

                        relation_type = str(triplet.action or "UnknownBehavior")
                        event_id = str(triplet.event_id or "")

                        subject_id = triplet.subject.get_id()
                        object_id = triplet.object.get_id()

                        if subject_id not in unique_node_ids:
                            unique_node_ids.add(subject_id)
                            node_type_counter[resolve_graph_entity_type(triplet.subject).value] += 1

                        if object_id not in unique_node_ids:
                            unique_node_ids.add(object_id)
                            node_type_counter[resolve_graph_entity_type(triplet.object).value] += 1

                        technique_unique_nodes.add(subject_id)
                        technique_unique_nodes.add(object_id)

                        subject_ids_all.add(subject_id)
                        object_ids_all.add(object_id)
                        technique_subject_ids.add(subject_id)
                        technique_object_ids.add(object_id)

                        relationship_type_counter[relation_type] += 1
                        event_id_counter[event_id] += 1
                        technique_relation_matrix[technique_name][relation_type] += 1

                        technique_relationships += 1

                    del log_entries
            finally:
                self._cleanup()

            root_count = len(technique_subject_ids - technique_object_ids)
            technique_summaries.append(
                TechniqueSummary(
                    technique_name=technique_name,
                    log_file_count=technique_log_files,
                    total_logs=technique_total_logs,
                    mapped_entities=technique_mapped_entities,
                    skipped_entities=technique_skipped_entities,
                    skipped_triplets=technique_skipped_triplets,
                    relationship_count=technique_relationships,
                    unique_node_count=len(technique_unique_nodes),
                    root_count=root_count,
                )
            )

        summary = {
            "dataset_folder": str(dataset_folder),
            "total_techniques": len(technique_summaries),
            "total_log_files": total_log_files,
            "total_logs": total_logs,
            "total_mapped_entities": total_mapped_entities,
            "total_skipped_entities": total_skipped_entities,
            "total_skipped_triplets": total_skipped_triplets,
            "total_nodes": len(unique_node_ids),
            "total_relationships": int(sum(relationship_type_counter.values())),
            "total_root_nodes": len(subject_ids_all - object_ids_all),
        }

        return {
            "summary": summary,
            "relationship_type_counts": sort_counter(relationship_type_counter),
            "node_type_counts": sort_counter(node_type_counter),
            "event_id_counts": sort_counter(event_id_counter),
            "technique_relationship_matrix": {
                technique_name: sort_counter(relation_counter)
                for technique_name, relation_counter in sorted(technique_relation_matrix.items())
            },
            "technique_summaries": [
                {
                    "technique_name": item.technique_name,
                    "log_file_count": item.log_file_count,
                    "total_logs": item.total_logs,
                    "mapped_entities": item.mapped_entities,
                    "skipped_entities": item.skipped_entities,
                    "skipped_triplets": item.skipped_triplets,
                    "relationship_count": item.relationship_count,
                    "unique_node_count": item.unique_node_count,
                    "root_count": item.root_count,
                }
                for item in sorted(technique_summaries, key=lambda x: x.technique_name)
            ],
            "top_relationship_types": [
                {"relation_type": relation_type, "count": count}
                for relation_type, count in relationship_type_counter.most_common(10)
            ],
            "top_node_types": [
                {"node_type": node_type, "count": count}
                for node_type, count in node_type_counter.most_common(10)
            ],
            "top_techniques_by_relationships": [
                {
                    "technique_name": item.technique_name,
                    "relationship_count": item.relationship_count,
                }
                for item in sorted(
                    technique_summaries,
                    key=lambda x: (-x.relationship_count, x.technique_name),
                )[:10]
            ],
        }


class Neo4jV1StatsCollector:
    def collect(
        self,
        uri: str,
        username: str | None,
        password: str | None,
        database: str,
        max_depth: int,
    ) -> dict[str, Any]:
        manager = Neo4jGraphManager(
            uri=uri,
            username=username,
            password=password,
            database=database,
        )

        try:
            graph_stats = manager.get_graph_stats()

            with manager._driver.session(database=manager._database) as session:
                relationship_rows = session.execute_read(
                    manager._run_all,
                    """
                    MATCH ()-[r]->()
                    RETURN type(r) AS relation_type, count(*) AS count
                    ORDER BY count DESC, relation_type ASC
                    """,
                    {},
                )

                node_type_rows = session.execute_read(
                    manager._run_all,
                    """
                    MATCH (n)
                    RETURN coalesce(n.type, head(labels(n)), 'UnknownEntity') AS node_type,
                           count(*) AS count
                    ORDER BY count DESC, node_type ASC
                    """,
                    {},
                )

                event_rows = session.execute_read(
                    manager._run_all,
                    """
                    MATCH ()-[r]->()
                    RETURN coalesce(toString(r.event_id), '') AS event_id, count(*) AS count
                    ORDER BY count DESC, event_id ASC
                    """,
                    {},
                )

                technique_rows = session.execute_read(
                    manager._run_all,
                    """
                    MATCH (t:Technique)
                    OPTIONAL MATCH (t)-[:HAS_ROOT]->(root)
                    RETURN coalesce(t.name, t.display_name, t.id) AS technique_name,
                           count(DISTINCT root) AS root_count
                    ORDER BY technique_name ASC
                    """,
                    {},
                )

                # Bound depth avoids exploring the entire graph on dense datasets.
                safe_depth = max(1, int(max_depth))
                matrix_rows = session.execute_read(
                    manager._run_all,
                    f"""
                    MATCH (t:Technique)
                    OPTIONAL MATCH (t)-[:HAS_ROOT]->(root)
                    OPTIONAL MATCH (root)-[*0..{safe_depth}]->(s)
                    WITH t, collect(DISTINCT root) + collect(DISTINCT s) AS seed_nodes
                    UNWIND seed_nodes AS node
                    WITH t, node
                    WHERE node IS NOT NULL
                    WITH DISTINCT t, node
                    MATCH (node)-[r]->()
                    WHERE type(r) <> 'HAS_ROOT'
                    RETURN coalesce(t.name, t.display_name, t.id) AS technique_name,
                           type(r) AS relation_type,
                           count(DISTINCT id(r)) AS count
                    ORDER BY technique_name ASC, relation_type ASC
                    """,
                    {},
                )

            relationship_type_counts = {
                str(item["relation_type"]): int(item["count"])
                for item in relationship_rows
            }
            node_type_counts = {
                str(item["node_type"]): int(item["count"])
                for item in node_type_rows
            }
            event_id_counts = {
                str(item["event_id"]): int(item["count"])
                for item in event_rows
            }

            technique_relationship_matrix: defaultdict[str, dict[str, int]] = defaultdict(dict)
            for item in matrix_rows:
                technique_name = str(item["technique_name"])
                relation_type = str(item["relation_type"])
                technique_relationship_matrix[technique_name][relation_type] = int(item["count"])

            matrix_totals = {
                technique_name: int(sum(relation_map.values()))
                for technique_name, relation_map in technique_relationship_matrix.items()
            }

            technique_summaries = []
            for item in technique_rows:
                technique_name = str(item["technique_name"])
                technique_summaries.append(
                    {
                        "technique_name": technique_name,
                        "root_count": int(item["root_count"]),
                        "relationship_count_from_roots": matrix_totals.get(technique_name, 0),
                    }
                )

            summary = {
                "neo4j_uri": uri,
                "neo4j_database": database,
                "total_nodes": int(graph_stats.get("node_count", 0)),
                "total_relationships": int(graph_stats.get("relationship_count", 0)),
                "total_techniques": len(technique_rows),
                "matrix_max_depth": max(1, int(max_depth)),
            }

            return {
                "summary": summary,
                "relationship_type_counts": dict(sorted(relationship_type_counts.items())),
                "node_type_counts": dict(sorted(node_type_counts.items())),
                "event_id_counts": dict(sorted(event_id_counts.items())),
                "technique_relationship_matrix": {
                    technique_name: dict(sorted(relation_map.items()))
                    for technique_name, relation_map in sorted(technique_relationship_matrix.items())
                },
                "technique_summaries": technique_summaries,
                "status": "ok",
            }
        except Exception as exc:
            return {
                "status": "error",
                "error": str(exc),
            }
        finally:
            manager.close()
