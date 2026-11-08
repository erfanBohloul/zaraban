"""Target configuration parser and validator for Zaraban.

Meets the project requirement (Section 2):
"افزودن یک برنامۀ جدید باید تنها با تغییر فایل پیکربندی، شامل دستور ساخت،
مسیر باینری، نحوۀ ارسال ورودی و مجموعۀ آزمون‌ها، ممکن باشد."
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import json


class InputMethod(str, Enum):
    STDIN = "stdin"
    ARGS = "args"
    FILE = "file"


@dataclass
class BuildConfig:
    binary_path: str
    release_cmd: str
    sanitized_cmd: str
    clean_cmd: Optional[str] = None


@dataclass
class TestCase:
    name: str
    input_data: Optional[str] = None
    input_file: Optional[str] = None
    args: list[str] = field(default_factory=list)
    expected_exit_code: int = 0
    expected_output: Optional[str] = None
    description: Optional[str] = None


@dataclass
class ResourceLimits:
    timeout_seconds: float = 3.0
    memory_limit_mb: int = 256


@dataclass
class TargetConfig:
    name: str
    build: BuildConfig
    input_method: InputMethod = InputMethod.STDIN
    file_arg_placeholder: str = "{input_file}"
    base_dir: str = "base"
    patch_dir: str = "patch"
    diff_file: Optional[str] = None
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    valid_tests: list[TestCase] = field(default_factory=list)
    boundary_tests: list[TestCase] = field(default_factory=list)
    security_tests: list[TestCase] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any], base_path: Optional[Path] = None) -> TargetConfig:
        build_raw = data.get("build", {})
        build = BuildConfig(
            binary_path=build_raw.get("binary_path", ""),
            release_cmd=build_raw.get("release_cmd", ""),
            sanitized_cmd=build_raw.get("sanitized_cmd", ""),
            clean_cmd=build_raw.get("clean_cmd")
        )

        limits_raw = data.get("limits", {})
        limits = ResourceLimits(
            timeout_seconds=float(limits_raw.get("timeout_seconds", 3.0)),
            memory_limit_mb=int(limits_raw.get("memory_limit_mb", 256))
        )

        def parse_tests(test_list: list[dict[str, Any]]) -> list[TestCase]:
            parsed = []
            for t in test_list:
                parsed.append(TestCase(
                    name=t.get("name", "unnamed_test"),
                    input_data=t.get("input_data"),
                    input_file=t.get("input_file"),
                    args=t.get("args", []),
                    expected_exit_code=int(t.get("expected_exit_code", 0)),
                    expected_output=t.get("expected_output"),
                    description=t.get("description")
                ))
            return parsed

        return cls(
            name=data.get("name", "unnamed_target"),
            build=build,
            input_method=InputMethod(data.get("input_method", "stdin")),
            file_arg_placeholder=data.get("file_arg_placeholder", "{input_file}"),
            base_dir=data.get("base_dir", "base"),
            patch_dir=data.get("patch_dir", "patch"),
            diff_file=data.get("diff_file"),
            limits=limits,
            valid_tests=parse_tests(data.get("valid_tests", [])),
            boundary_tests=parse_tests(data.get("boundary_tests", [])),
            security_tests=parse_tests(data.get("security_tests", []))
        )

    @classmethod
    def from_file(cls, path: str | Path) -> TargetConfig:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        
        content = p.read_text(encoding="utf-8")
        if p.suffix in [".yaml", ".yml"]:
            try:
                import yaml
                data = yaml.safe_load(content)
            except ImportError:
                # Basic fallback if pyyaml not installed yet
                raise RuntimeError("PyYAML is required to parse .yaml configuration files.")
        else:
            data = json.loads(content)
            
        return cls.from_dict(data, base_path=p.parent)
