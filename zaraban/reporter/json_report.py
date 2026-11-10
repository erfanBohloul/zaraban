"""Structured JSON reporting module for Zaraban."""

from __future__ import annotations
from pathlib import Path
import json
from zaraban.core.validator import ValidationSummary


class JsonReporter:
    """Generates machine-readable JSON reports for CI/CD pipeline automation."""

    @classmethod
    def save_report(cls, summary: ValidationSummary, output_path: str | Path):
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = summary.to_dict()
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
