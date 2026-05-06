from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from pipeline import TechniqueGraphPipeline
from storage import PatternStore


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
DEFAULT_DATASET_CANDIDATES = [
    Path(r"D:\NCKH_new\attack_data_full\datasets\attack_techniques"),
    Path(r"D:\ki8\nckh\new_pineline\auditlog\attack_data\datasets\attack_techniques"),
    Path(r"D:\Capstone Project & NCKH\attack_data\datasets\attack_techniques"),
]


def _resolve_dataset_folder() -> Path:
    configured = os.environ.get("ATTACK_DATASET_FOLDER", "").strip()
    if configured:
        return Path(configured)

    for candidate in DEFAULT_DATASET_CANDIDATES:
        if candidate.exists():
            return candidate

    return DEFAULT_DATASET_CANDIDATES[0]


DATASET_FOLDER = _resolve_dataset_folder()
DATA_DIR = PROJECT_DIR / "data"
FRONTEND_DIR = PROJECT_DIR / "frontend"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
    CORS(app)

    pipeline = TechniqueGraphPipeline(dataset_folder=DATASET_FOLDER)
    pattern_store = PatternStore(data_dir=DATA_DIR)

    @app.get("/api/techniques")
    def get_techniques():
        return jsonify(
            {
                "techniques": pipeline.list_techniques(),
                "dataset_folder": str(DATASET_FOLDER),
            }
        )

    @app.get("/api/graph")
    def get_graph():
        technique = (request.args.get("technique") or "").strip()
        if not technique:
            return jsonify({"error": "Query parameter 'technique' is required."}), 400

        try:
            graph = pipeline.build_graph(technique)
        except FileNotFoundError:
            return jsonify(
                {
                    "error": (
                        f"Technique '{technique}' not found in Sysmon dataset: {DATASET_FOLDER}"
                    )
                }
            ), 404
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify(graph)

    @app.get("/api/patterns")
    def get_patterns():
        technique = (request.args.get("technique") or "").strip()
        if not technique:
            return jsonify({"error": "Query parameter 'technique' is required."}), 400

        patterns = pattern_store.get_patterns(technique)
        return jsonify({"technique": technique, "patterns": patterns})

    @app.post("/api/patterns")
    def save_patterns():
        payload = request.get_json(silent=True) or {}
        technique = str(payload.get("technique", "")).strip()
        patterns = payload.get("patterns", [])

        if not technique:
            return jsonify({"error": "Field 'technique' is required."}), 400
        if not isinstance(patterns, list):
            return jsonify({"error": "Field 'patterns' must be a list."}), 400

        saved = pattern_store.save_patterns(technique, patterns)
        return jsonify({"technique": technique, "patterns": saved})

    @app.post("/api/patterns/append")
    def append_pattern():
        payload = request.get_json(silent=True) or {}
        technique = str(payload.get("technique", "")).strip()
        new_pattern = str(payload.get("new_pattern", "")).strip()

        if not technique:
            return jsonify({"error": "Field 'technique' is required."}), 400
        if not new_pattern:
            return jsonify({"error": "Field 'new_pattern' is required."}), 400

        saved = pattern_store.append_pattern(technique, new_pattern)
        return jsonify({"technique": technique, "patterns": saved})

    # ── Whitelist routes ────────────────────────────────────────────────────

    @app.get("/api/whitelist")
    def get_whitelist():
        technique = (request.args.get("technique") or "").strip()
        if not technique:
            return jsonify({"error": "Query parameter 'technique' is required."}), 400

        whitelist = pattern_store.get_whitelist(technique)
        return jsonify({"technique": technique, "whitelist": whitelist})

    @app.post("/api/whitelist")
    def save_whitelist():
        payload = request.get_json(silent=True) or {}
        technique = str(payload.get("technique", "")).strip()
        whitelist = payload.get("whitelist", [])

        if not technique:
            return jsonify({"error": "Field 'technique' is required."}), 400
        if not isinstance(whitelist, list):
            return jsonify({"error": "Field 'whitelist' must be a list."}), 400

        saved = pattern_store.save_whitelist(technique, whitelist)
        return jsonify({"technique": technique, "whitelist": saved})

    @app.post("/api/whitelist/append")
    def append_whitelist():
        payload = request.get_json(silent=True) or {}
        technique = str(payload.get("technique", "")).strip()
        new_pattern = str(payload.get("new_pattern", "")).strip()

        if not technique:
            return jsonify({"error": "Field 'technique' is required."}), 400
        if not new_pattern:
            return jsonify({"error": "Field 'new_pattern' is required."}), 400

        saved = pattern_store.append_whitelist_item(technique, new_pattern)
        return jsonify({"technique": technique, "whitelist": saved})

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
    app.run(host="127.0.0.1", port=5000, debug=True)
