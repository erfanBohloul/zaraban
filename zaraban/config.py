"""Target configuration: load and strictly validate a target's ``zaraban.yaml``.

A target is described by one config file. Adding a new target needs only a
new config and the target's own files, never a change to the tool. Validation
is strict: any problem stops the run with exit code 30 before anything is
built, and all problems are reported together.

This module turns the YAML into a validated :class:`Target`, and resolves each
test entry into a ready-to-run :class:`models.TestCase` (input read to bytes).
It does not build or run anything.
"""

from __future__ import annotations

import difflib
import re
import typing
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

import yaml
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError

from . import models
from .models import ErrorCode, InputMethod, OutputMatch, TestKind, ZarabanError

MAX_INPUT_BYTES = 1 << 20  # 1 MB

# Names are used in output paths, so only ASCII letters, digits, _ and -.
_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")

# Keys removed from the schema; a config that still uses them is an error.
REMOVED_KEYS = {
    "patch_dir": "patch_dir is no longer supported; give the patch on the command line "
                 "with --patch",
    "diff_file": "diff_file is no longer supported; give the patch on the command line "
                 "with --patch",
}


# ---------------------------------------------------------------------------
# The YAML schema (pydantic, extra keys forbidden so typos are errors)
# ---------------------------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _check_name(v: str) -> str:
    if not _NAME_RE.fullmatch(v):
        raise ValueError(f"{v!r} is not a valid name: use only ASCII letters, digits, "
                         "_ and - (names become file and directory names)")
    return v


Name = Annotated[str, AfterValidator(_check_name)]


class _TestSpec(_Strict):
    name: Name
    description: Optional[str] = None
    input_file: Optional[str] = None
    input_data: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    expected_exit_code: Optional[int] = None
    expected_output: Optional[str] = None
    output_match: Literal["contains", "exact"] = "contains"


class _BuildSpec(_Strict):
    binary_path: str
    release_cmd: str
    sanitized_cmd: str
    clean_cmd: Optional[str] = None
    coverage_cmd: Optional[str] = None  # coverage build for the execution trace


class _LimitsSpec(_Strict):
    timeout_seconds: float = Field(default=3.0, gt=0)
    memory_limit_mb: int = Field(default=256, gt=0)


class _ConfigSpec(_Strict):
    name: Name
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
    (regression tests from ``regression_dir`` are added later, by regression.py).
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
        """Config tests, in run order: valid, boundary, invalid, security."""
        return list(self._tests)

    @classmethod
    def load(cls, path: str | Path) -> tuple["Target", list[models.Issue]]:
        """Load and validate a config file.

        Returns the target and a list of non-fatal warnings. Raises
        :class:`ZarabanError` (code ``CONFIG_INVALID``, exit 30) if the config
        is invalid, with every problem found listed in ``details["problems"]``.
        """
        config_path = Path(path)
        if not config_path.is_file():
            what = "is a directory, not a file" if config_path.is_dir() else "does not exist"
            raise ZarabanError(ErrorCode.CONFIG_INVALID, f"cannot load the config {path}",
                               {"problems": [f"{path} {what}; give the path of the "
                                             "target's zaraban.yaml with -c/--config"]})

        raw = _read_yaml(config_path)
        problems: list[str] = []

        spec: Optional[_ConfigSpec] = None
        if not isinstance(raw, dict):
            problems.append("the file is empty or is not a YAML mapping; it must hold keys "
                            "such as name, build, valid_tests and security_tests")
        else:
            try:
                spec = _ConfigSpec.model_validate(raw)
            except ValidationError as exc:
                problems.extend(_format_errors(exc, _ConfigSpec, raw))

        warnings: list[models.Issue] = []
        tests: list[models.TestCase] = []
        if spec is not None:
            # Semantic checks pydantic cannot do on its own.
            problems.extend(_check_unique_names(spec))
            problems.extend(_check_base_dir(spec, config_path.parent))
            tests, resolve_problems = _resolve_tests(spec, config_path.parent)
            problems.extend(resolve_problems)
            warnings.extend(_schema_warnings(spec))

        if problems:
            raise ZarabanError(
                ErrorCode.CONFIG_INVALID,
                f"the config {config_path} has {_count(len(problems), 'problem')}",
                {"problems": problems},
            )

        assert spec is not None
        return cls(spec, config_path, tests), warnings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_yaml(path: Path) -> Any:
    """Read the config. A file that cannot be read or parsed is a config
    error (exit 30), not a bug in the tool."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ZarabanError(ErrorCode.CONFIG_INVALID, f"cannot load {path}",
                           {"problems": ["the file is not UTF-8 text"]})
    except OSError as exc:
        raise ZarabanError(ErrorCode.CONFIG_INVALID, f"cannot load {path}",
                           {"problems": [f"the file cannot be read: {exc.strerror or exc}"]})
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ZarabanError(ErrorCode.CONFIG_INVALID, f"cannot load {path}",
                           {"problems": [f"the file is not valid YAML: {_one_line(str(exc))}"]})


def _format_errors(exc: ValidationError, model: type[BaseModel], raw: Any = None) -> list[str]:
    """One readable line per schema error of ``model``: where it is (with the
    test's name for a test entry), and what is wrong in plain words."""
    out = []
    for err in exc.errors():
        loc = tuple(err["loc"])
        kind = err["type"]
        if kind == "extra_forbidden":
            key = str(loc[-1]) if loc else ""
            where, what = _where(loc[:-1], raw), _unknown_key(key, _model_at(model, loc[:-1]))
            out.append(f"{where}: {what}" if where else what)
            continue
        if kind == "missing":
            what = "required key is missing"
        elif kind == "value_error" and "error" in err.get("ctx", {}):
            what = str(err["ctx"]["error"])  # our own message
        elif kind == "too_short" and loc and loc[-1] in dict(_KIND_FIELDS).values():
            what = "must list at least one test"
        elif kind in ("model_type", "dict_type"):
            what = f"must be a mapping of keys to values{_got(err)}"
        else:
            msg = str(err["msg"])
            if msg.startswith("Input should be "):
                msg = "must be " + msg[len("Input should be "):]
            if msg.startswith("must be a valid "):
                msg = msg.split(", ", 1)[0]  # drop pydantic's "unable to parse ..." tail
            what = msg + _got(err)
        out.append(f"{_where(loc, raw) or '(top level)'}: {what}")
    return out


def _where(loc: tuple, raw: Any) -> str:
    """``valid_tests[2] (minify_spaces).input_file`` for a schema location."""
    text = ""
    node = raw
    for part in loc:
        if isinstance(part, int):
            text += f"[{part}]"
            node = node[part] if isinstance(node, list) and part < len(node) else None
            if isinstance(node, dict) and isinstance(node.get("name"), str):
                text += f" ({node['name']})"
        else:
            text += f".{part}" if text else str(part)
            node = node.get(part) if isinstance(node, dict) else None
    return text


def _model_at(model: Optional[type[BaseModel]], loc: tuple) -> Optional[type[BaseModel]]:
    """The schema model of the mapping at ``loc``, or None if it is not one."""
    for part in loc:
        if model is None:
            return None
        if isinstance(part, int):
            continue
        field_info = model.model_fields.get(str(part))
        model = _inner_model(field_info.annotation) if field_info else None
    return model


def _inner_model(annotation: Any) -> Optional[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for arg in typing.get_args(annotation):
        found = _inner_model(arg)
        if found is not None:
            return found
    return None


def _unknown_key(key: str, model: Optional[type[BaseModel]]) -> str:
    if key in REMOVED_KEYS:
        return REMOVED_KEYS[key]
    text = f"unknown key {key!r}"
    if model is not None:
        close = difflib.get_close_matches(key, list(model.model_fields), n=1, cutoff=0.6)
        if close:
            text += f"; did you mean {close[0]!r}?"
    return text


def _got(err: dict) -> str:
    """`` (got 'x')`` for a short scalar input; empty for anything else."""
    value = err.get("input")
    if isinstance(value, (str, int, float, bool)) and len(repr(value)) <= 40:
        return f" (got {value!r})"
    return ""


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _check_unique_names(spec: _ConfigSpec) -> list[str]:
    seen: dict[str, int] = {}
    for _, field_name in _KIND_FIELDS:
        for t in getattr(spec, field_name):
            seen[t.name] = seen.get(t.name, 0) + 1
    return [f"test name {name!r} is used by {n} tests; every test needs its own name"
            for name, n in seen.items() if n > 1]


def _check_base_dir(spec: _ConfigSpec, config_dir: Path) -> list[str]:
    base = config_dir / spec.base_dir
    if not base.is_dir():
        return [f"base_dir: {spec.base_dir!r} is not a directory (it is relative to the "
                f"config's directory, {config_dir})"]
    return []


def _resolve_tests(
    spec: _ConfigSpec, config_dir: Path
) -> tuple[list[models.TestCase], list[str]]:
    """Turn each test entry into a TestCase with its input read to bytes."""
    tests: list[models.TestCase] = []
    problems: list[str] = []
    method = InputMethod(spec.input_method)

    for kind, field_name in _KIND_FIELDS:
        for t in getattr(spec, field_name):
            if t.input_file and t.input_data is not None:
                problems.append(f"test {t.name}: give either input_file or input_data, "
                                "not both")
                continue

            data: Optional[bytes] = None
            ext = ""
            source: Optional[str] = None
            if t.input_file:
                fpath = (config_dir / t.input_file).resolve()
                source = t.input_file
                ext = fpath.suffix
                if not fpath.exists():
                    problems.append(f"test {t.name}: input_file {t.input_file!r} does not "
                                    f"exist (it is relative to the config's directory, "
                                    f"{config_dir})")
                    continue
                if not fpath.is_file():
                    problems.append(f"test {t.name}: input_file {t.input_file!r} is not a "
                                    "regular file")
                    continue
                try:
                    data = fpath.read_bytes()
                except OSError as exc:
                    problems.append(f"test {t.name}: input_file {t.input_file!r} cannot be "
                                    f"read ({exc.strerror or exc})")
                    continue
                if len(data) > MAX_INPUT_BYTES:
                    problems.append(f"test {t.name}: input_file {t.input_file!r} is "
                                    f"{len(data)} bytes; the limit is 1 MB ({MAX_INPUT_BYTES} "
                                    "bytes)")
                    continue
            elif t.input_data is not None:
                data = t.input_data.encode("utf-8")
            elif method is InputMethod.FILE:
                problems.append(f"test {t.name}: input_method is 'file', so the test needs "
                                "input_file or input_data")
                continue

            if method is InputMethod.ARGS and data is not None and b"\x00" in data:
                problems.append(f"test {t.name}: input_method is 'args', so the input is "
                                "passed as a command-line argument and cannot contain a NUL "
                                "byte; use 'file' or 'stdin' instead")
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
    return tests, problems


def _schema_warnings(spec: _ConfigSpec) -> list[models.Issue]:
    warnings: list[models.Issue] = []
    if not spec.invalid_tests:
        warnings.append(models.Issue(
            models.WarningCode.NO_INVALID_TESTS.value,
            "the config has no invalid_tests; add malformed inputs the program must "
            "reject, so a patch that breaks its error handling is caught",
            {"config": spec.name},
        ))
    if spec.repeats == 1:
        warnings.append(models.Issue(
            models.WarningCode.REPEATS_TOO_LOW.value,
            "repeats is 1, so a result that changes from run to run (flaky) cannot be "
            "detected; use 3 or more",
            {"config": spec.name},
        ))
    return warnings
