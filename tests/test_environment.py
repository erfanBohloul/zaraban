"""Unit tests for environment gathering (SPEC §12.4)."""

import platform

from zaraban import environment
from zaraban.models import EnvironmentInfo


def test_12_4_gather_fills_core_fields():
    env = environment.gather()
    assert isinstance(env, EnvironmentInfo)
    # The facts that always exist.
    assert env.arch == platform.machine()
    assert env.python == platform.python_version()
    assert env.kernel and isinstance(env.kernel, str)
    assert env.os and isinstance(env.os, str)


def test_12_4_tool_versions_are_str_or_none():
    env = environment.gather()
    for v in (env.gcc, env.clang, env.llvm_symbolizer):
        assert v is None or isinstance(v, str)


def test_12_4_docker_image_from_env(monkeypatch):
    monkeypatch.setenv(environment.DOCKER_IMAGE_ENV, "zaraban:phase2")
    assert environment.gather().docker_image == "zaraban:phase2"


def test_12_4_docker_image_absent_is_none(monkeypatch):
    monkeypatch.delenv(environment.DOCKER_IMAGE_ENV, raising=False)
    assert environment.gather().docker_image is None


# -- tool_version ------------------------------------------------------------

def test_tool_version_missing_tool_is_none():
    assert environment.tool_version("this-tool-does-not-exist-zaraban") is None


def test_tool_version_present_tool_returns_first_line():
    # python3 is certainly on PATH inside the container; its --version is one line.
    v = environment.tool_version("python3")
    assert v is not None
    assert "Python" in v
    assert "\n" not in v  # only the first line
