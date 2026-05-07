from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

try:
    from .pipeline import PureAttackTreePipeline
except ImportError:  # pragma: no cover - fallback for direct script execution
    from pipeline import PureAttackTreePipeline


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

# Keep dataset source aligned with the original inspect_log_gui backend.
DATASET_FOLDER = Path(r"D:\NCKH_new\attack_data_full\datasets\attack_techniques")
DATA_DIR = PROJECT_DIR / "data"
OUTPUT_DIR = PROJECT_DIR / "clean_attack_tree"
FRONTEND_DIR = PROJECT_DIR / "pure_attack_frontend"


def _parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
    CORS(app)

    pipeline = PureAttackTreePipeline(
        dataset_folder=DATASET_FOLDER,
        data_dir=DATA_DIR,
        output_dir=OUTPUT_DIR,
    )

    @app.get("/api/pure/techniques")
    def get_techniques():
        techniques = pipeline.list_techniques()
        payload = []
        for technique in techniques:
            output_file = pipeline.output_file_path(technique)
            payload.append(
                {
                    "name": technique,
                    "saved": output_file.exists(),
                    "output_file": str(output_file),
                }
            )

        return jsonify(
            {
                "techniques": payload,
                "dataset_folder": str(DATASET_FOLDER),
                "output_folder": str(OUTPUT_DIR),
            }
        )

    @app.get("/api/pure/graph")
    def get_graph():
        technique = str(request.args.get("technique", "")).strip()
        rebuild = _parse_bool(request.args.get("rebuild"), default=False)

        if not technique:
            return jsonify({"error": "Query parameter 'technique' is required."}), 400

        try:
            graph = pipeline.get_graph(technique=technique, rebuild=rebuild)
        except FileNotFoundError:
            return jsonify(
                {
                    "error": (
                        f"Technique '{technique}' not found in Sysmon dataset: {DATASET_FOLDER}"
                    )
                }
            ), 404
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 500

        return jsonify(graph)

    @app.post("/api/pure/build")
    def build_one():
        payload = request.get_json(silent=True) or {}
        technique = str(payload.get("technique", "")).strip()
        force_rebuild = _parse_bool(payload.get("force_rebuild"), default=True)

        if not technique:
            return jsonify({"error": "Field 'technique' is required."}), 400

        try:
            graph = pipeline.get_graph(technique=technique, rebuild=force_rebuild)
        except FileNotFoundError:
            return jsonify(
                {
                    "error": (
                        f"Technique '{technique}' not found in Sysmon dataset: {DATASET_FOLDER}"
                    )
                }
            ), 404
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 500

        return jsonify(
            {
                "technique": technique,
                "output_file": str(pipeline.output_file_path(technique)),
                "graph": graph,
            }
        )

    @app.post("/api/pure/build-all")
    def build_all():
        payload = request.get_json(silent=True) or {}
        force_rebuild = _parse_bool(payload.get("force_rebuild"), default=False)

        techniques_raw = payload.get("techniques")
        techniques: list[str] | None = None
        if isinstance(techniques_raw, list):
            techniques = [str(item).strip() for item in techniques_raw if str(item).strip()]

        try:
            result = pipeline.build_all(techniques=techniques, force_rebuild=force_rebuild)
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 500

        return jsonify(result)

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/<path:asset_path>")
    def static_assets(asset_path: str):
        file_path = FRONTEND_DIR / asset_path
        if file_path.exists() and file_path.is_file():
            return send_from_directory(FRONTEND_DIR, asset_path)
        return jsonify({"error": "Not found"}), 404

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
