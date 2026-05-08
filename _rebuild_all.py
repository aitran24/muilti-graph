import sys
sys.path.insert(0, '.')
from pathlib import Path
from inspect_log_gui.pure_attack_backend.pipeline import PureAttackTreePipeline

pipeline = PureAttackTreePipeline(
    dataset_folder=Path('D:/NCKH_new/attack_data_full/datasets/attack_techniques'),
    data_dir=Path('D:/NCKH_new/muilti-graph/inspect_log_gui/data'),
    output_dir=Path('D:/NCKH_new/muilti-graph/inspect_log_gui/clean_attack_tree')
)
result = pipeline.build_all(force_rebuild=True)
built = result.get('built', 0)
errors = result.get('errors', [])
print(f'Built: {built}, Errors: {len(errors)}')
for e in errors:
    print(f'  ERR {e.get("technique","?")} : {e.get("error","?")}')
print('Done.')
