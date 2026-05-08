from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from statistics.common import (
    discover_run_json_files,
    extract_version_from_name,
    render_table,
    render_technique_relation_matrix,
    safe_pct_change,
)


def load_history_runs(stats_dir: Path) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []

    for file_path in discover_run_json_files(stats_dir):
        with file_path.open("r", encoding="utf-8") as file:
            payload = json.load(file)

        run_block = payload.get("run", {})
        if "version" not in run_block:
            version = extract_version_from_name(file_path.name)
            run_block["version"] = version if version is not None else -1
            payload["run"] = run_block

        payload["_file_path"] = str(file_path)
        runs.append(payload)

    runs.sort(key=lambda item: int(item.get("run", {}).get("version", -1)))
    return runs


def _build_count_delta_rows(prev_counts: dict[str, int], curr_counts: dict[str, int]) -> list[list[Any]]:
    keys = sorted(set(prev_counts.keys()) | set(curr_counts.keys()))
    rows: list[list[Any]] = []

    for key in keys:
        prev_val = int(prev_counts.get(key, 0))
        curr_val = int(curr_counts.get(key, 0))
        delta = curr_val - prev_val
        rows.append([key, prev_val, curr_val, f"{delta:+d}", safe_pct_change(prev_val, curr_val)])

    rows.sort(key=lambda row: (-(abs(int(row[3]))), row[0]))
    return rows


def _extract_summary_metrics(payload: dict[str, Any]) -> tuple[int, int, int]:
    current = payload.get("current_pipeline", {})
    current_status = str(current.get("status", "ok")).lower()
    if current_status == "ok":
        summary = current.get("summary", {})
        return (
            int(summary.get("total_nodes", 0)),
            int(summary.get("total_relationships", 0)),
            int(summary.get("total_techniques", 0)),
        )

    trees = payload.get("clean_attack_trees", {})
    trees_status = str(trees.get("status", "ok")).lower()
    if trees_status == "ok" and trees:
        summary = trees.get("summary", {})
        return (
            int(summary.get("total_attack_nodes", 0)),
            int(summary.get("total_attack_edges", 0)),
            int(summary.get("total_techniques", 0)),
        )

    neo = payload.get("neo4j_v1", {})
    neo_status = str(neo.get("status", "")).lower()
    if neo_status == "ok":
        summary = neo.get("summary", {})
        return (
            int(summary.get("total_nodes", 0)),
            int(summary.get("total_relationships", 0)),
            int(summary.get("total_techniques", 0)),
        )

    return (0, 0, 0)


def _compute_reduction(prev: int, curr: int) -> tuple[int, str]:
    if prev <= 0:
        if curr <= 0:
            return (0, "0.00%")
        return (0, "N/A")

    if curr >= prev:
        return (0, "0.00%")

    reduced = prev - curr
    reduced_pct = (reduced / prev) * 100.0
    return (reduced, f"{reduced_pct:.2f}%")


def _build_overall_change_row(version_label: str, metric_name: str, prev: int, curr: int) -> list[Any]:
    delta = curr - prev
    reduced, reduced_pct = _compute_reduction(prev, curr)
    return [
        version_label,
        metric_name,
        prev,
        curr,
        f"{delta:+d}",
        safe_pct_change(prev, curr),
        reduced,
        reduced_pct,
    ]


def _sum_technique_matrix(matrix: dict[str, dict[str, int]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for technique, rel_counts in matrix.items():
        totals[str(technique)] = sum(int(v) for v in rel_counts.values())
    return totals


def _extract_technique_relationship_counts(payload: dict[str, Any]) -> dict[str, int]:
    current = payload.get("current_pipeline", {})
    current_status = str(current.get("status", "ok")).lower()
    if current_status == "ok":
        summaries = current.get("technique_summaries", [])
        if summaries:
            return {
                str(item.get("technique_name", "")): int(item.get("relationship_count", 0))
                for item in summaries
                if str(item.get("technique_name", ""))
            }

        matrix = current.get("technique_relationship_matrix", {})
        if matrix:
            return _sum_technique_matrix(matrix)

    neo = payload.get("neo4j_v1", {})
    neo_status = str(neo.get("status", "")).lower()
    if neo_status == "ok":
        matrix = neo.get("technique_relationship_matrix", {})
        return _sum_technique_matrix(matrix)

    return {}


def _extract_technique_metric_counts(payload: dict[str, Any], metric_key: str) -> dict[str, int]:
    current = payload.get("current_pipeline", {})
    current_status = str(current.get("status", "ok")).lower()
    if current_status != "ok":
        return {}

    summaries = current.get("technique_summaries", [])
    return {
        str(item.get("technique_name", "")): int(item.get(metric_key, 0))
        for item in summaries
        if str(item.get("technique_name", ""))
    }


def _select_count_block(payload: dict[str, Any], key: str) -> dict[str, int]:
    current = payload.get("current_pipeline", {})
    current_status = str(current.get("status", "ok")).lower()
    if current_status == "ok":
        return {str(k): int(v) for k, v in current.get(key, {}).items()}

    neo = payload.get("neo4j_v1", {})
    neo_status = str(neo.get("status", "")).lower()
    if neo_status == "ok":
        return {str(k): int(v) for k, v in neo.get(key, {}).items()}

    return {}


def _history_generated_marker(runs: list[dict[str, Any]]) -> str:
    for payload in reversed(runs):
        created_at = str(payload.get("run", {}).get("created_at_utc", "")).strip()
        if created_at:
            return created_at
    return "(unknown)"


def render_new_report_markdown(payload: dict[str, Any]) -> str:
    run = payload["run"]
    current = payload.get("current_pipeline", {})
    current_status = str(current.get("status", "ok")).lower()
    neo4j_v1 = payload.get("neo4j_v1")

    summary = current.get("summary", {})
    dataset_folder = summary.get("dataset_folder", "") if summary else ""

    lines: list[str] = []
    lines.append(f"# Dataset Statistics v{run['version']}")
    lines.append("")
    lines.append("## Run Metadata")
    lines.append("")
    lines.append(
        render_table(
            ["Field", "Value"],
            [
                ["Version", run["version"]],
                ["Name", run.get("name", "") or "(none)"],
                ["Created At (UTC)", run["created_at_utc"]],
                ["Mode", run["mode"]],
                ["Dataset Folder", dataset_folder or "(none)"],
            ],
        )
    )
    lines.append("")

    if current_status == "ok":
        lines.append("## Current Pipeline Summary")
        lines.append("")
        lines.append(
            render_table(
                ["Metric", "Value"],
                [
                    ["Total Techniques", summary.get("total_techniques", 0)],
                    ["Total Log Files", summary.get("total_log_files", 0)],
                    ["Total Logs", summary.get("total_logs", 0)],
                    ["Mapped Entities", summary.get("total_mapped_entities", 0)],
                    ["Skipped Entities", summary.get("total_skipped_entities", 0)],
                    ["Skipped Triplets", summary.get("total_skipped_triplets", 0)],
                    ["Total Nodes", summary.get("total_nodes", 0)],
                    ["Total Relationships", summary.get("total_relationships", 0)],
                    ["Total Root Nodes", summary.get("total_root_nodes", 0)],
                ],
            )
        )
        lines.append("")

        lines.append("## Relationship Counts By Type")
        lines.append("")
        lines.append(
            render_table(
                ["Relationship Type", "Count"],
                [[k, v] for k, v in current.get("relationship_type_counts", {}).items()]
                or [["(no data)", 0]],
            )
        )
        lines.append("")

        lines.append("## Node Counts By Type")
        lines.append("")
        lines.append(
            render_table(
                ["Node Type", "Count"],
                [[k, v] for k, v in current.get("node_type_counts", {}).items()] or [["(no data)", 0]],
            )
        )
        lines.append("")

        lines.append("## Event ID Distribution")
        lines.append("")
        lines.append(
            render_table(
                ["Event ID", "Count"],
                [[k, v] for k, v in current.get("event_id_counts", {}).items()] or [["(no data)", 0]],
            )
        )
        lines.append("")

        lines.append("## Technique Summary")
        lines.append("")
        lines.append(
            render_table(
                [
                    "Technique",
                    "Log Files",
                    "Total Logs",
                    "Mapped Entities",
                    "Skipped Entities",
                    "Skipped Triplets",
                    "Relationships",
                    "Unique Nodes",
                    "Root Nodes",
                ],
                [
                    [
                        item["technique_name"],
                        item["log_file_count"],
                        item["total_logs"],
                        item["mapped_entities"],
                        item["skipped_entities"],
                        item["skipped_triplets"],
                        item["relationship_count"],
                        item["unique_node_count"],
                        item["root_count"],
                    ]
                    for item in current.get("technique_summaries", [])
                ]
                or [["(no data)", 0, 0, 0, 0, 0, 0, 0, 0]],
            )
        )
        lines.append("")

        lines.append("## Technique x Relationship Matrix")
        lines.append("")
        lines.append(render_technique_relation_matrix(current.get("technique_relationship_matrix", {})))
        lines.append("")

        lines.append("## Top Relationship Types")
        lines.append("")
        lines.append(
            render_table(
                ["Relationship Type", "Count"],
                [
                    [item["relation_type"], item["count"]]
                    for item in current.get("top_relationship_types", [])
                ]
                or [["(no data)", 0]],
            )
        )
        lines.append("")
    else:
        lines.append("## Current Pipeline")
        lines.append("")
        if current_status == "skipped":
            lines.append(
                f"Current pipeline statistics skipped: {current.get('reason', 'No reason provided')}"
            )
        else:
            lines.append("Current pipeline statistics unavailable.")
        lines.append("")

    if neo4j_v1:
        lines.append("## Neo4j v1 Statistics")
        lines.append("")

        status = str(neo4j_v1.get("status", "")).lower()
        if status == "skipped":
            lines.append(
                f"Neo4j statistics collection skipped: {neo4j_v1.get('reason', 'No reason provided')}"
            )
            lines.append("")
        elif status != "ok":
            lines.append(f"Neo4j statistics collection failed: {neo4j_v1.get('error', 'Unknown error')}")
            lines.append("")
        else:
            neo_summary = neo4j_v1["summary"]
            lines.append(
                render_table(
                    ["Metric", "Value"],
                    [
                        ["Neo4j URI", neo_summary["neo4j_uri"]],
                        ["Neo4j Database", neo_summary["neo4j_database"]],
                        ["Total Nodes", neo_summary["total_nodes"]],
                        ["Total Relationships", neo_summary["total_relationships"]],
                        ["Total Techniques", neo_summary["total_techniques"]],
                        ["Technique Matrix Max Depth", neo_summary["matrix_max_depth"]],
                    ],
                )
            )
            lines.append("")

            lines.append("### Neo4j Relationship Counts By Type")
            lines.append("")
            lines.append(
                render_table(
                    ["Relationship Type", "Count"],
                    [[k, v] for k, v in neo4j_v1["relationship_type_counts"].items()] or [["(no data)", 0]],
                )
            )
            lines.append("")

            lines.append("### Neo4j Node Counts By Type")
            lines.append("")
            lines.append(
                render_table(
                    ["Node Type", "Count"],
                    [[k, v] for k, v in neo4j_v1["node_type_counts"].items()] or [["(no data)", 0]],
                )
            )
            lines.append("")

            lines.append("### Neo4j Technique x Relationship Matrix")
            lines.append("")
            lines.append(render_technique_relation_matrix(neo4j_v1["technique_relationship_matrix"]))
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_history_report_markdown(runs: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("# Dataset Statistics History")
    lines.append("")
    lines.append(f"Generated from latest version timestamp (UTC): {_history_generated_marker(runs)}")
    lines.append("")

    if not runs:
        lines.append("No versioned statistics files were found.")
        lines.append("")
        return "\n".join(lines)

    timeline_rows: list[list[Any]] = []
    for idx, payload in enumerate(runs):
        run = payload.get("run", {})
        curr_nodes, curr_relationships, curr_techniques = _extract_summary_metrics(payload)

        if idx == 0:
            node_delta_pct = "N/A"
            rel_delta_pct = "N/A"
            tech_delta_pct = "N/A"
        else:
            prev_nodes, prev_relationships, prev_techniques = _extract_summary_metrics(runs[idx - 1])
            node_delta_pct = safe_pct_change(prev_nodes, curr_nodes)
            rel_delta_pct = safe_pct_change(prev_relationships, curr_relationships)
            tech_delta_pct = safe_pct_change(prev_techniques, curr_techniques)

        timeline_rows.append(
            [
                run.get("version", ""),
                run.get("name") or "(none)",
                run.get("mode") or "(unknown)",
                run.get("created_at_utc", ""),
                curr_nodes,
                node_delta_pct,
                curr_relationships,
                rel_delta_pct,
                curr_techniques,
                tech_delta_pct,
            ]
        )

    lines.append("## Version Timeline")
    lines.append("")
    lines.append(
        render_table(
            [
                "Version",
                "Name",
                "Mode",
                "Created At (UTC)",
                "Total Nodes",
                "Delta Nodes %",
                "Total Relationships",
                "Delta Relationships %",
                "Total Techniques",
                "Delta Techniques %",
            ],
            timeline_rows,
        )
    )
    lines.append("")

    if len(runs) >= 2:
        lines.append("## Overall Change (Consecutive Versions)")
        lines.append("")

        overall_rows: list[list[Any]] = []
        for idx in range(1, len(runs)):
            prev_payload = runs[idx - 1]
            curr_payload = runs[idx]
            prev_run = prev_payload.get("run", {})
            curr_run = curr_payload.get("run", {})
            prev_nodes, prev_relationships, prev_techniques = _extract_summary_metrics(prev_payload)
            curr_nodes, curr_relationships, curr_techniques = _extract_summary_metrics(curr_payload)

            version_label = f"v{prev_run.get('version', '?')} -> v{curr_run.get('version', '?')}"
            overall_rows.append(_build_overall_change_row(version_label, "Total Nodes", prev_nodes, curr_nodes))
            overall_rows.append(
                _build_overall_change_row(
                    version_label,
                    "Total Relationships",
                    prev_relationships,
                    curr_relationships,
                )
            )
            overall_rows.append(
                _build_overall_change_row(version_label, "Total Techniques", prev_techniques, curr_techniques)
            )

        lines.append(
            render_table(
                [
                    "Version Pair",
                    "Metric",
                    "Prev",
                    "Curr",
                    "Delta",
                    "Delta %",
                    "Reduced",
                    "Reduced %",
                ],
                overall_rows,
            )
        )
        lines.append("")

        lines.append("## Overall Change (Baseline v1)")
        lines.append("")

        baseline_rows: list[list[Any]] = []
        base_payload = runs[0]
        base_run = base_payload.get("run", {})
        base_nodes, base_relationships, base_techniques = _extract_summary_metrics(base_payload)

        for idx in range(1, len(runs)):
            curr_payload = runs[idx]
            curr_run = curr_payload.get("run", {})
            curr_nodes, curr_relationships, curr_techniques = _extract_summary_metrics(curr_payload)

            version_label = f"v{base_run.get('version', '?')} -> v{curr_run.get('version', '?')}"
            baseline_rows.append(_build_overall_change_row(version_label, "Total Nodes", base_nodes, curr_nodes))
            baseline_rows.append(
                _build_overall_change_row(
                    version_label,
                    "Total Relationships",
                    base_relationships,
                    curr_relationships,
                )
            )
            baseline_rows.append(
                _build_overall_change_row(version_label, "Total Techniques", base_techniques, curr_techniques)
            )

        lines.append(
            render_table(
                [
                    "Baseline Pair",
                    "Metric",
                    "Prev",
                    "Curr",
                    "Delta",
                    "Delta %",
                    "Reduced",
                    "Reduced %",
                ],
                baseline_rows,
            )
        )
        lines.append("")
    else:
        lines.append("## Comparison Status")
        lines.append("")
        lines.append("Only one version is available, so change/reduction comparisons are not shown yet.")
        lines.append(
            "Run at least one more version to enable: overall reduction (nodes/relationships/techniques), baseline-v1 comparison, and per-technique delta tables."
        )
        lines.append("")

    if len(runs) >= 2:
        lines.append("## Detailed Delta By Consecutive Version")
        lines.append("")

        for idx in range(1, len(runs)):
            prev_payload = runs[idx - 1]
            curr_payload = runs[idx]
            prev_run = prev_payload.get("run", {})
            curr_run = curr_payload.get("run", {})

            lines.append(f"### v{prev_run.get('version', '?')} -> v{curr_run.get('version', '?')}")
            lines.append("")

            prev_tech_rel_counts = _extract_technique_relationship_counts(prev_payload)
            curr_tech_rel_counts = _extract_technique_relationship_counts(curr_payload)
            lines.append("Technique Delta (Relationship Count)")
            lines.append("")
            lines.append(
                render_table(
                    ["Technique", "Prev", "Curr", "Delta", "Delta %"],
                    _build_count_delta_rows(prev_tech_rel_counts, curr_tech_rel_counts)
                    or [["(no data)", 0, 0, "+0", "0.00%"]],
                )
            )
            lines.append("")

            prev_tech_unique_nodes = _extract_technique_metric_counts(prev_payload, "unique_node_count")
            curr_tech_unique_nodes = _extract_technique_metric_counts(curr_payload, "unique_node_count")
            if prev_tech_unique_nodes or curr_tech_unique_nodes:
                lines.append("Technique Delta (Unique Node Count)")
                lines.append("")
                lines.append(
                    render_table(
                        ["Technique", "Prev", "Curr", "Delta", "Delta %"],
                        _build_count_delta_rows(prev_tech_unique_nodes, curr_tech_unique_nodes)
                        or [["(no data)", 0, 0, "+0", "0.00%"]],
                    )
                )
                lines.append("")

            prev_rel_counts = _select_count_block(prev_payload, "relationship_type_counts")
            curr_rel_counts = _select_count_block(curr_payload, "relationship_type_counts")
            lines.append("Relationship Type Delta")
            lines.append("")
            lines.append(
                render_table(
                    ["Relationship Type", "Prev", "Curr", "Delta", "Delta %"],
                    _build_count_delta_rows(prev_rel_counts, curr_rel_counts)
                    or [["(no data)", 0, 0, "+0", "0.00%"]],
                )
            )
            lines.append("")

            prev_node_counts = _select_count_block(prev_payload, "node_type_counts")
            curr_node_counts = _select_count_block(curr_payload, "node_type_counts")
            lines.append("Node Type Delta")
            lines.append("")
            lines.append(
                render_table(
                    ["Node Type", "Prev", "Curr", "Delta", "Delta %"],
                    _build_count_delta_rows(prev_node_counts, curr_node_counts)
                    or [["(no data)", 0, 0, "+0", "0.00%"]],
                )
            )
            lines.append("")

            prev_event_counts = _select_count_block(prev_payload, "event_id_counts")
            curr_event_counts = _select_count_block(curr_payload, "event_id_counts")
            lines.append("Event ID Delta")
            lines.append("")
            lines.append(
                render_table(
                    ["Event ID", "Prev", "Curr", "Delta", "Delta %"],
                    _build_count_delta_rows(prev_event_counts, curr_event_counts)
                    or [["(no data)", 0, 0, "+0", "0.00%"]],
                )
            )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"
