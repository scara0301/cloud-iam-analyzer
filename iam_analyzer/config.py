"""Runtime configuration, sourced from environment variables.

In Kubernetes these values are injected from the ConfigMap in k8s/configmap.yaml.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_title: str
    default_contamination: float
    sample_seed: int
    max_rows: int


def load_settings() -> Settings:
    return Settings(
        app_title=os.environ.get("APP_TITLE", "Cloud Security Posture & IAM Analyzer"),
        default_contamination=min(max(_float_env("DEFAULT_CONTAMINATION", 0.03), 0.001), 0.5),
        sample_seed=int(_float_env("SAMPLE_SEED", 42)),
        max_rows=int(_float_env("MAX_ROWS", 200_000)),
    )
