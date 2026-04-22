from __future__ import annotations

import gc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from globals.global_object import clear_all_globals
from globals.logger_manager import LoggerManager
from graph_db.neo4j_manager import Neo4jGraphManager
from log_parsers.sysmon_parser import SysmonLogParser
from triplet_creator.triplet_creator import SysmonTripletCreator


logger = LoggerManager.get_logger(__name__)

_SUPPORTED_LOG_SUFFIXES = {".log", ".txt", ".xml"}


@dataclass
class FileIngestResult:
    technique_name: str
    log_file: str
    total_logs: int
    inserted_count: int
    failed_insert_count: int
    skipped_count: int
    root_count: int
    attached_root_count: int


def _find_sysmon_logs(folder: Path) -> list[Path]:
    return sorted(
        file_path
        for file_path in folder.rglob("*")
        if file_path.is_file()
        and "sysmon" in file_path.name.lower()
        and file_path.suffix.lower() in _SUPPORTED_LOG_SUFFIXES
    )


def _ingest_single_log(
    parser: SysmonLogParser,
    triplet_creator: SysmonTripletCreator,
    technique_name: str,
    log_file: Path,
) -> FileIngestResult:
    inserted_count = 0
    failed_insert_count = 0
    skipped_count = 0

    subject_ids: set[str] = set()
    object_ids: set[str] = set()

    log_entries = parser.parse_from_file(str(log_file))

    for log_entry in log_entries:
        entity = parser.map_entity(log_entry)
        if not entity:
            skipped_count += 1
            continue

        triplet = triplet_creator.create_triplet(entity)
        if not triplet:
            skipped_count += 1
            continue

        if triplet_creator.store_triplet(triplet):
            inserted_count += 1
            subject_ids.add(triplet.subject.get_id())
            object_ids.add(triplet.object.get_id())
        else:
            failed_insert_count += 1

    root_ids = sorted(subject_ids - object_ids)
    attached_root_count = triplet_creator.graph_manager.attach_roots_to_technique(
        technique_name=technique_name,
        root_node_ids=root_ids,
    )

    result = FileIngestResult(
        technique_name=technique_name,
        log_file=str(log_file),
        total_logs=len(log_entries),
        inserted_count=inserted_count,
        failed_insert_count=failed_insert_count,
        skipped_count=skipped_count,
        root_count=len(root_ids),
        attached_root_count=attached_root_count,
    )

    logger.info(
        "[DatasetPipeline] technique=%s | log=%s | total=%s | inserted=%s | failed=%s | skipped=%s | roots=%s | attached=%s",
        result.technique_name,
        result.log_file,
        result.total_logs,
        result.inserted_count,
        result.failed_insert_count,
        result.skipped_count,
        result.root_count,
        result.attached_root_count,
    )

    del log_entries
    del subject_ids
    del object_ids

    return result


def _cleanup_after_subfolder() -> None:
    clear_all_globals()
    gc.collect()


def run_dataset_pipeline(
    dataset_folder: str,
    neo4j_manager: Neo4jGraphManager,
) -> list[dict[str, Any]]:
    dataset_path = Path(dataset_folder)
    if not dataset_path.exists() or not dataset_path.is_dir():
        raise FileNotFoundError(f"Dataset folder does not exist: {dataset_folder}")

    parser = SysmonLogParser()
    triplet_creator = SysmonTripletCreator(graph_manager=neo4j_manager)

    all_results: list[dict[str, Any]] = []

    technique_folders = sorted(path for path in dataset_path.iterdir() if path.is_dir())
    for technique_folder in technique_folders:
        technique_name = technique_folder.name
        sysmon_logs = _find_sysmon_logs(technique_folder)

        if not sysmon_logs:
            logger.info(
                "[DatasetPipeline] Skip folder without Sysmon logs: %s",
                technique_folder,
            )
            _cleanup_after_subfolder()
            continue

        try:
            for log_file in sysmon_logs:
                result = _ingest_single_log(
                    parser=parser,
                    triplet_creator=triplet_creator,
                    technique_name=technique_name,
                    log_file=log_file,
                )
                all_results.append(asdict(result))
        finally:
            # Avoid cross-folder entity carry-over and free memory pressure.
            _cleanup_after_subfolder()
            del sysmon_logs

    return all_results
