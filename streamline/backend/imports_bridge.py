from __future__ import annotations

import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_ORIGINAL_CWD = Path.cwd()
os.chdir(REPO_ROOT)
try:
    from class_define.object_definition import BaseEntity  # noqa: E402
    from globals.global_object import clear_all_globals  # noqa: E402
    from inspect_log_gui.backend.pipeline import TechniqueGraphPipeline  # noqa: E402
    from log_parsers.sysmon_parser import SysmonLogParser  # noqa: E402
    from triplet_creator.triplet_creator import SysmonTripletCreator, Triplet  # noqa: E402
finally:
    os.chdir(_ORIGINAL_CWD)


__all__ = [
    "BaseEntity",
    "Triplet",
    "TechniqueGraphPipeline",
    "SysmonLogParser",
    "SysmonTripletCreator",
    "clear_all_globals",
    "REPO_ROOT",
]
