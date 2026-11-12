"""Target configuration: load and strictly validate a target's ``zaraban.yaml``.

A target is described by one config file (SPEC §4). Adding a new target must
need only a new config and the target's own files, no tool code (course spec
§2). Validation is strict: any problem stops the run with exit code 30 before
anything is built, and all problems are reported together (SPEC §4.5).

This module turns the YAML into a validated :class:`Target`, and resolves each
test entry into a ready-to-run :class:`models.TestCase` (input read to bytes).
It does not build or run anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from . import models
from .models import ErrorCode, InputMethod, OutputMatch, TestKind, ZarabanError

MAX_INPUT_BYTES = 1 << 20  # 1 MB (SPEC §5.2)

# Keys removed from the schema; a config that still uses them is an error (§4.5).
REMOVED_KEYS = {
    "patch_dir": "patch_dir was removed; pass the patch on the command line with --patch",
    "diff_file": "diff_file was removed; pass the patch on the command line with --patch",
}


# ---------------------------------------------------------------------------
# The YAML schema (pydantic, extra keys forbidden so typos are errors, §4.5)
# ---------------------------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _TestSpec(_Strict):
    name: str
    description: Optional[str] = None
    input_file: Optional[str] = None
    input_data: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    expected_exit_code: Optional[int] = None
    expected_output: Optional[str] = None
    output_match: Literal["contains", "exact"] = "contains"

    @field_validator("name")
    @classmethod
    def _name_chars(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c in "_-" for c in v):
            raise ValueError("name may contain only letters, digits, _ and -")
        return v


class _BuildSpec(_Strict):
    binary_path: str
    release_cmd: str
    sanitized_cmd: str
    clean_cmd: Optional[str] = None


class _LimitsSpec(_Strict):
    timeout_seconds: float = Field(default=3.0, gt=0)
    memory_limit_mb: int = Field(default=256, gt=0)


class _ConfigSpec(_Strict):
    name: str
    base_dir: str = "."
    input_method: Literal["file", "stdin", "args"] = "stdin"
    file_arg_placeholder: str = "{input_file}"
    repeats: int = Field(default=3, ge=1)
    env: dict[str, str] = Field(default_factory=dict)
    regression_dir: str = "tests/regression"
    build: _BuildSpec
    limits: _LimitsSpec = Field(default_factory=_LimitsSpec)
    valid_tests: list[_TestSpec] = Field(min_length=1)
    boundary_tests: list[_TestSpec] = Field(default_factory=list)
    invalid_tests: list[_TestSpec] = Field(default_factory=list)
    security_tests: list[_TestSpec] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def _name_chars(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c in "_-" for c in v):
            raise ValueError("name may contain only letters, digits, _ and -")
        return v


# ---------------------------------------------------------------------------
# The validated, resolved target the rest of the tool uses
# ---------------------------------------------------------------------------

_KIND_FIELDS = (
    (TestKind.VALID, "valid_tests"),
    (TestKind.BOUNDARY, "boundary_tests"),
    (TestKind.INVALID, "invalid_tests"),
    (TestKind.SECURITY, "security_tests"),
)


class Target:
    """A validated target config, with tests resolved to bytes.

    Build it with :meth:`load`. ``spec`` is the raw validated schema;
    :meth:`all_tests` returns the config tests as :class:`models.TestCase`
    (regression tests from ``regression_dir`` are added later, by §10).
    """

    def __init__(self, spec: _ConfigSpec, config_path: Path, tests: list[models.TestCase]):
        self.spec = spec
        self.config_path = config_path
        self.config_dir = config_path.parent
        self._tests = tests

    # convenience accessors
    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def input_method(self) -> InputMethod:
        return InputMethod(self.spec.input_method)

    @property
    def base_dir(self) -> Path:
        return (self.config_dir / self.spec.base_dir).resolve()

    def all_tests(self) -> list[models.TestCase]:
        """Config tests, in SPEC order: valid, boundary, invalid, security."""
        return list(self._tests)

    @classmethod
    def load(cls, path: str | Path) -> tuple["Target", list[models.Issue]]:
        """Load and validate a config file.

        Returns the target and a list of non-fatal warnings. Raises
        :class:`ZarabanError` (code ``CONFIG_INVALID``, exit 30) if the config
        is invalid, with every problem found listed in ``details["problems"]``.
        """
        config_path = Path(path)
        if not config_path.exists():
            raise ZarabanError(ErrorCode.CONFIG_INVALID, f"config file not found: {path}",
                               {"problems": [f"{path}: file not found"]})

        raw = _read_yaml(config_path)
        problems: list[str] = []

        # Friendlier message for removed keys, before pydantic's generic one.
        if isinstance(raw, dict):
            for key, msg in REMOVED_KEYS.items():
                if key in raw:
                    problems.append(msg)

        spec: Optional[_ConfigSpec] = None
        try:
            spec = _ConfigSpec.model_validate(raw)
        except ValidationError as exc:
            problems.extend(_format_errors(exc))

        warnings: list[models.Issue] = []
        tests: list[models.TestCase] = []
        if spec is not None:
            # Semantic checks pydantic cannot do on its own.
            problems.extend(_check_unique_names(spec))
            tests, resolve_problems, resolve_warnings = _resolve_tests(spec, config_path.parent)
            problems.extend(resolve_problems)
            warnings.extend(resolve_warnings)
            warnings.extend(_schema_warnings(spec))

        if problems:
            raise ZarabanError(
                ErrorCode.CONFIG_INVALID,
                f"{len(problems)} problem(s) in {config_path}",
                {"problems": problems},
            )

        assert spec is not None
        return cls(spec, config_path, tests), warnings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ZarabanError(ErrorCode.CONFIG_INVALID, f"{path}: not valid YAML",
                           {"problems": [f"{path}: YAML parse error: {exc}"]})


def _format_errors(exc: ValidationError) -> list[str]:
    out = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        if err["type"] == "extra_forbidden":
            field = err["loc"][-1] if err["loc"] else ""
            hint = REMOVED_KEYS.get(str(field))
            out.append(f"{loc}: unknown key" + (f" ({hint})" if hint else ""))
        else:
            out.append(f"{loc or '(root)'}: {err['msg']}")
    return out


def _check_unique_names(spec: _ConfigSpec) -> list[str]:
    seen: dict[str, int] = {}
    for _, field_name in _KIND_FIELDS:
        for t in getattr(spec, field_name):
            seen[t.name] = seen.get(t.name, 0) + 1
    return [f"test name {name!r} is used {n} times" for name, n in seen.items() if n > 1]


def _resolve_tests(
    spec: _ConfigSpec, config_dir: Path
) -> tuple[list[models.TestCase], list[str], list[models.Issue]]:
    tests: list[models.TestCase] = []
    problems: list[str] = []
    warnings: list[models.Issue] = []
    method = InputMethod(spec.input_method)

    for kind, field_name in _KIND_FIELDS:
        for t in getattr(spec, field_name):
            if t.input_file and t.input_data is not None:
                problems.append(f"{t.name}: has both input_file and input_data")
                continue

            data: Optional[bytes] = None
            ext = ""
            source: Optional[str] = None
            if t.input_file:
                fpath = (config_dir / t.input_file).resolve()
                source = t.input_file
                ext = fpath.suffix
                if not fpath.exists():
                    problems.append(f"{t.name}: input_file does not exist: {t.input_file}")
                    continue
                data = fpath.read_bytes()
                if len(data) > MAX_INPUT_BYTES:
                    problems.append(f"{t.name}: input_file is larger than 1 MB")
                    continue
            elif t.input_data is not None:
                data = t.input_data.encode("utf-8")
            elif method is InputMethod.FILE:
                problems.append(f"{t.name}: input_method is 'file' but the test gives no input")
                continue

            if method is InputMethod.ARGS and data is not None and b"\x00" in data:
                problems.append(f"{t.name}: input_method is 'args' but the input contains a NUL byte")
                continue

            tests.append(models.TestCase(
                name=t.name,
                kind=kind,
                input_bytes=data,
                input_ext=ext,
                args=list(t.args),
                description=t.description,
                source_path=source,
                expected_exit_code=t.expected_exit_code,
                expected_output=t.expected_output,
                output_match=OutputMatch(t.output_match),
            ))
    return tests, problems, warnings


def _schema_warnings(spec: _ConfigSpec) -> list[models.Issue]:
    warnings: list[models.Issue] = []
    if not spec.invalid_tests:
        warnings.append(models.Issue(
            models.WarningCode.NO_INVALID_TESTS.value,
            "the config has no invalid_tests; the spec asks the team to design invalid inputs",
            {"config": spec.name},
        ))
    if spec.repeats == 1:
        warnings.append(models.Issue(
            models.WarningCode.REPEATS_TOO_LOW.value,
            "repeats is 1, so flaky results cannot be detected",
            {"config": spec.name},
        ))
    return warnings
