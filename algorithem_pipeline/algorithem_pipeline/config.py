from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PipelineConfig:
    repo_root: Path
    pattern_dir: Path
    dataset_dir: Path

    @staticmethod
    def from_repo_root(repo_root: Path) -> "PipelineConfig":
        return PipelineConfig(
            repo_root=repo_root,
            pattern_dir=repo_root / "inspect_log_gui" / "clean_attack_tree",
            dataset_dir=repo_root.parent / "attack_data" / "datasets" / "attack_techniques",
        )
