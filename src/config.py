"""
config.py — .secretscan.toml configuration.

Python 3.11+ provides tomllib in the standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


@dataclass
class ScanConfig:
    entropy_threshold: float = 4.3
    min_entropy_len: int = 20
    max_file_size_mb: float = 5.0
    ignore_dirs: list[str] = field(default_factory=list)
    baseline_file: str = ".secretscan-baseline.json"
    html_report: str = "secretscan-report.html"


def load_config(root: str) -> ScanConfig:
    """Load .secretscan.toml from the scan root, if present."""
    config = ScanConfig()
    path = os.path.join(root, ".secretscan.toml")

    if not os.path.isfile(path) or tomllib is None:
        return config

    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return config

    scan = data.get("scan", {})
    report = data.get("report", {})
    baseline = data.get("baseline", {})

    if "entropy_threshold" in scan:
        config.entropy_threshold = float(scan["entropy_threshold"])
    if "min_entropy_len" in scan:
        config.min_entropy_len = int(scan["min_entropy_len"])
    if "max_file_size_mb" in scan:
        config.max_file_size_mb = float(scan["max_file_size_mb"])
    if isinstance(scan.get("ignore_dirs"), list):
        config.ignore_dirs = [str(x) for x in scan["ignore_dirs"]]
    if "file" in baseline:
        config.baseline_file = str(baseline["file"])
    if "html" in report:
        config.html_report = str(report["html"])

    return config
