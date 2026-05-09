from __future__ import annotations

import argparse
from pathlib import Path

from statistics.collectors import CleanAttackTreeStatsCollector, CurrentPipelineStatsCollector, Neo4jV1StatsCollector
from statistics.common import (
    OUTPUT_DIRNAME,
    discover_run_json_files,
    extract_version_from_name,
    slugify,
    utc_now_iso,
    write_json,
    write_text,
)
from statistics.reports import (
    load_history_runs,
    render_compare_report_markdown,
    render_history_report_markdown,
    render_new_report_markdown,
)


def _collect_neo4j(args: argparse.Namespace) -> dict:
    return Neo4jV1StatsCollector().collect(
        uri=args.neo4j_uri,
        username=args.neo4j_username,
        password=args.neo4j_password,
        database=args.neo4j_database,
        max_depth=args.neo4j_matrix_depth,
    )


def _empty_current_pipeline_block(reason: str) -> dict:
    return {
        "status": "skipped",
        "reason": reason,
        "summary": {
            "dataset_folder": "",
            "total_techniques": 0,
            "total_log_files": 0,
            "total_logs": 0,
            "total_mapped_entities": 0,
            "total_skipped_entities": 0,
            "total_skipped_triplets": 0,
            "total_nodes": 0,
            "total_relationships": 0,
            "total_root_nodes": 0,
        },
        "relationship_type_counts": {},
        "node_type_counts": {},
        "event_id_counts": {},
        "technique_relationship_matrix": {},
        "technique_summaries": [],
        "top_relationship_types": [],
        "top_node_types": [],
        "top_techniques_by_relationships": [],
    }


def _build_base_name(version: int, run_name: str) -> str:
    slug = slugify(run_name) if run_name else ""
    return f"stat_v{version}" + (f"_{slug}" if slug else "")


def _existing_versions(output_dir: Path) -> list[int]:
    versions: list[int] = []
    for file_path in discover_run_json_files(output_dir):
        version = extract_version_from_name(file_path.name)
        if version is not None:
            versions.append(version)
    return sorted(set(versions))


def _next_version(output_dir: Path) -> int:
    versions = _existing_versions(output_dir)
    return max(versions, default=0) + 1


def _run_new_mode(args: argparse.Namespace, output_dir: Path, version: int) -> None:
    dataset_folder = Path(args.dataset_folder)
    base_name = _build_base_name(version, args.name)

    current_pipeline_stats = CurrentPipelineStatsCollector().collect(dataset_folder)
    current_pipeline_stats["status"] = "ok"

    neo4j_v1 = {
        "status": "skipped",
        "reason": "--skip-neo4j was set",
    }
    if not args.skip_neo4j:
        neo4j_v1 = _collect_neo4j(args)

    payload = {
        "schema_version": 1,
        "run": {
            "mode": "new",
            "version": version,
            "name": args.name or "",
            "created_at_utc": utc_now_iso(),
        },
        "current_pipeline": current_pipeline_stats,
        "neo4j_v1": neo4j_v1,
    }

    markdown_output = render_new_report_markdown(payload)

    json_path = output_dir / f"{base_name}.json"
    markdown_path = output_dir / f"{base_name}.md"

    write_json(json_path, payload)
    write_text(markdown_path, markdown_output)

    print(f"[NEW] Version: v{version}")
    print(f"[NEW] JSON: {json_path}")
    print(f"[NEW] Markdown: {markdown_path}")


def _run_neo4j_only_mode(args: argparse.Namespace, output_dir: Path, version: int) -> None:
    base_name = _build_base_name(version, args.name)

    payload = {
        "schema_version": 1,
        "run": {
            "mode": "neo4j-only",
            "version": version,
            "name": args.name or "",
            "created_at_utc": utc_now_iso(),
        },
        "current_pipeline": _empty_current_pipeline_block("--neo4j-only was set"),
        "neo4j_v1": _collect_neo4j(args),
    }

    markdown_output = render_new_report_markdown(payload)

    json_path = output_dir / f"{base_name}.json"
    markdown_path = output_dir / f"{base_name}.md"

    write_json(json_path, payload)
    write_text(markdown_path, markdown_output)

    print(f"[NEO4J-ONLY] Version: v{version}")
    print(f"[NEO4J-ONLY] JSON: {json_path}")
    print(f"[NEO4J-ONLY] Markdown: {markdown_path}")


def _run_compare_mode(output_dir: Path) -> None:
    runs = load_history_runs(output_dir)
    if not runs:
        raise RuntimeError("No run files found. Run --neo4j-only or --new first.")
    if len(runs) < 2:
        raise RuntimeError("At least 2 versioned stat files are required for comparison.")

    first_version = int(runs[0].get("run", {}).get("version", 1))
    last_version = int(runs[-1].get("run", {}).get("version", first_version))
    output_path = output_dir / f"comparison_v{first_version}_v{last_version}.md"

    compare_markdown = render_compare_report_markdown(runs)
    write_text(output_path, compare_markdown)

    print(f"[COMPARE] Loaded versions: {len(runs)}")
    print(f"[COMPARE] Markdown: {output_path}")


def _run_history_mode(output_dir: Path) -> None:
    runs = load_history_runs(output_dir)
    if not runs:
        raise RuntimeError("No run files found. Run --neo4j-only or --new first.")

    history_markdown = render_history_report_markdown(runs)
    first_version = int(runs[0].get("run", {}).get("version", 1))
    last_version = int(runs[-1].get("run", {}).get("version", first_version))
    output_path = output_dir / f"history_from_v{first_version}_v{last_version}.md"

    write_text(output_path, history_markdown)

    print(f"[HISTORY] Loaded versions: {len(runs)}")
    print(f"[HISTORY] Markdown: {output_path}")


def _run_from_trees_mode(args: argparse.Namespace, output_dir: Path, version: int) -> None:
    tree_dir = Path(args.tree_folder)
    base_name = _build_base_name(version, "")

    tree_stats = CleanAttackTreeStatsCollector().collect(tree_dir)
    tree_stats["status"] = "ok"

    summary = tree_stats["summary"]
    current_pipeline_stats = {
        "status": "ok",
        "summary": {
            "dataset_folder": summary["tree_dir"],
            "total_techniques": summary["total_techniques"],
            "total_log_files": summary.get("total_source_files", 0),
            "total_logs": summary["total_source_nodes"],
            "total_mapped_entities": summary["total_attack_nodes"],
            "total_skipped_entities": summary["total_source_nodes"] - summary["total_attack_nodes"],
            "total_skipped_triplets": summary["total_source_edges"] - summary["total_attack_edges"],
            "total_nodes": summary["total_attack_nodes"],
            "total_relationships": summary["total_attack_edges"],
            "total_root_nodes": summary["total_roots"],
        },
        "relationship_type_counts": tree_stats["relation_type_counts"],
        "node_type_counts": tree_stats["node_type_counts"],
        "event_id_counts": tree_stats["event_id_counts"],
        "technique_relationship_matrix": tree_stats["technique_relationship_matrix"],
        "technique_summaries": [
            {
                "technique_name": item["technique_name"],
                "log_file_count": item["source_file_count"],
                "total_logs": item["source_nodes"],
                "mapped_entities": item["attack_nodes"],
                "skipped_entities": item["source_nodes"] - item["attack_nodes"],
                "skipped_triplets": item["source_edges"] - item["attack_edges"],
                "relationship_count": item["attack_edges"],
                "unique_node_count": item["attack_nodes"],
                "root_count": item["roots"],
            }
            for item in tree_stats["technique_summaries"]
        ],
        "top_relationship_types": tree_stats["top_relation_types"],
        "top_node_types": [
            {"node_type": node_type, "count": count}
            for node_type, count in tree_stats["node_type_counts"].items()
        ],
        "top_techniques_by_relationships": [
            {
                "technique_name": item["technique_name"],
                "relationship_count": item["attack_edges"],
            }
            for item in sorted(
                tree_stats["technique_summaries"],
                key=lambda x: (-x["attack_edges"], x["technique_name"]),
            )[:10]
        ],
    }

    payload = {
        "schema_version": 1,
        "run": {
            "mode": "from-trees",
            "version": version,
            "name": args.name or "",
            "created_at_utc": utc_now_iso(),
        },
        "current_pipeline": current_pipeline_stats,
        "neo4j_v1": {"status": "skipped", "reason": "--from-trees does not query Neo4j"},
    }

    markdown_output = render_new_report_markdown(payload)

    json_path = output_dir / f"{base_name}.json"
    markdown_path = output_dir / f"{base_name}.md"

    write_json(json_path, payload)
    write_text(markdown_path, markdown_output)

    print(f"[FROM-TREES] Version: v{version}")
    print(f"[FROM-TREES] Techniques processed: {summary['total_techniques']}")
    skipped = summary.get("skipped_files", [])
    if skipped:
        print(f"[FROM-TREES] Skipped files: {skipped}")
    print(f"[FROM-TREES] JSON: {json_path}")
    print(f"[FROM-TREES] Markdown: {markdown_path}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independent statistics pipeline for dataset graph extraction and versioned reporting.",
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--new",
        action="store_true",
        help="Run full extraction pipeline and create a new versioned stats report.",
    )
    mode_group.add_argument(
        "--neo4j-only",
        action="store_true",
        help="Collect Neo4j v1 statistics only and create a new versioned report.",
    )
    mode_group.add_argument(
        "--history",
        action="store_true",
        help="Build history report from existing versioned stats files.",
    )
    mode_group.add_argument(
        "--from-trees",
        action="store_true",
        dest="from_trees",
        help="Collect statistics from pre-built clean_attack_tree JSON files (fast, no log re-parsing).",
    )
    mode_group.add_argument(
        "--compare",
        action="store_true",
        help="Generate a comparison report across all existing versioned stat files.",
    )

    parser.add_argument(
        "--dataset-folder",
        type=str,
        help="Path to technique dataset folder. Required only for --new.",
    )
    parser.add_argument(
        "--tree-folder",
        type=str,
        help="Path to clean_attack_tree directory. Required only for --from-trees.",
    )
    parser.add_argument(
        "--name",
        type=str,
        default="",
        help="Optional run name used in report metadata and output file suffix.",
    )

    parser.add_argument("--skip-neo4j", action="store_true", help="Skip Neo4j v1 statistics query block.")
    parser.add_argument(
        "--neo4j-uri",
        type=str,
        default="neo4j://127.0.0.1:7687",
        help="Neo4j URI for v1 snapshot queries.",
    )
    parser.add_argument(
        "--neo4j-username",
        type=str,
        default="neo4j",
        help="Neo4j username for v1 snapshot queries.",
    )
    parser.add_argument(
        "--neo4j-password",
        type=str,
        default="",
        help="Neo4j password for v1 snapshot queries.",
    )
    parser.add_argument(
        "--neo4j-database",
        type=str,
        default="neo4j",
        help="Neo4j database for v1 snapshot queries.",
    )
    parser.add_argument(
        "--neo4j-matrix-depth",
        type=int,
        default=6,
        help="Max traversal depth when building Technique x Relationship matrix from Neo4j roots.",
    )

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    stats_dir = Path(__file__).resolve().parent
    output_dir = stats_dir / OUTPUT_DIRNAME
    output_dir.mkdir(parents=True, exist_ok=True)
    versions = _existing_versions(output_dir)

    if args.neo4j_only:
        version = 1 if not versions else _next_version(output_dir)
        _run_neo4j_only_mode(args, output_dir, version)
        return

    if args.new:
        if not args.dataset_folder:
            parser.error("--dataset-folder is required when using --new")

        _run_new_mode(args, output_dir, _next_version(output_dir))
        return

    if getattr(args, "from_trees", False):
        if not args.tree_folder:
            parser.error("--tree-folder is required when using --from-trees")

        _run_from_trees_mode(args, output_dir, _next_version(output_dir))
        return

    if args.history:
        _run_history_mode(output_dir)
        return

    if args.compare:
        _run_compare_mode(output_dir)
