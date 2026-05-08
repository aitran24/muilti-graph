"""Apply extension-based core_effect fixes for 12 techniques."""
import sys
sys.path.insert(0, '.')
from pathlib import Path
from inspect_log_gui.backend.storage import PatternStore

ps = PatternStore(data_dir=Path('D:/NCKH_new/muilti-graph/inspect_log_gui/data'))

FIXES = {
    "T1021.003": [".dll"],
    "T1048.003": [".js", "evil.com"],
    "T1053.006": [".service"],
    "T1059.005": [".vbs", "dynwrapx.dll"],
    "T1068":     [".sys"],
    "T1505.003": [".aspx", "postex_"],
    "T1546.004": [".sh"],
    "T1548.001": ["setcap", "cap_setuid"],
    "T1564.004": [".ps1"],
    "T1566.001": ["officesetup.exe", ".doc"],
    "T1569.002": ["sa.dat", ".exe"],
    "T1574.006": [".sh"],
}

for technique, new_ce in FIXES.items():
    # Validate each pattern is substring of existing patterns
    existing = [p.lower() for p in ps.get_patterns(technique)]
    valid = [ce for ce in new_ce if any(ce.lower() in ep for ep in existing)]
    invalid = [ce for ce in new_ce if not any(ce.lower() in ep for ep in existing)]
    if invalid:
        print(f"  WARN {technique}: not in patterns → {invalid}")
    ps.save_core_effect(technique, valid)
    print(f"  OK   {technique}: {valid}")
