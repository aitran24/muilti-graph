"""Rebuild all clean_attack_tree JSONs with the new core_effect_node_ids field."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from inspect_log_gui.pure_attack_backend.pipeline import PureAttackTreePipeline

DATASET = Path(r"D:\NCKH_new\attack_data_full\datasets\attack_techniques")
DATA_DIR = Path(r"D:\NCKH_new\muilti-graph\inspect_log_gui\data")
OUTPUT_DIR = Path(r"D:\NCKH_new\muilti-graph\inspect_log_gui\clean_attack_tree")

pipeline = PureAttackTreePipeline(dataset_folder=DATASET, data_dir=DATA_DIR, output_dir=OUTPUT_DIR)
techniques = pipeline.list_techniques()

print(f"Total techniques: {len(techniques)}")
built, errors = [], []

for t in techniques:
    print(f"  Building {t}...", end=" ", flush=True)
    try:
        graph = pipeline.build_and_save(t)
        n = len(graph.get("nodes", []))
        ce = len(graph.get("matching", {}).get("core_effect_node_ids", []))
        print(f"nodes={n}, core_effect={ce}")
        built.append(t)
    except Exception as e:
        print(f"ERROR: {e}")
        errors.append((t, str(e)))

print(f"\nDone. Built={len(built)}, Errors={len(errors)}")
for t, e in errors:
    print(f"  ERROR {t}: {e}")
