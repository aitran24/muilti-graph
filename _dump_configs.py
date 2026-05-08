import json
from pathlib import Path

data_dir = Path('D:/NCKH_new/muilti-graph/inspect_log_gui/data')
configs = sorted(data_dir.glob('*_malcious_config.json'))

for cfg in configs:
    technique = cfg.stem.replace('_malcious_config', '')
    try:
        d = json.loads(cfg.read_text(encoding='utf-8'))
        patterns = d.get('patterns', [])
        core_effect = d.get('core_effect', [])
        print(f'\n=== {technique} ===')
        print(f'  patterns: {patterns}')
        if core_effect:
            print(f'  core_effect: {core_effect}')
    except Exception as e:
        print(f'\n=== {technique} === ERROR: {e}')
