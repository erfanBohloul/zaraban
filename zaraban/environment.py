"""Record the environment the run happened in (SPEC §12.4).

The report pins what produced its results: the OS and kernel, the architecture,
the Docker image (when the run sets ``ZARABAN_DOCKER_IMAGE``), the versions
of Python and the compilers (gcc, clang), and the path of the
``llvm-symbolizer`` the runs use. A missing tool is recorded as ``None``,
not an error — the build stage is what fails when a
required tool is absent, not this.

This module only reads version strings; it builds and runs nothing of the
target.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from typing import Optional

from .models import EnvironmentInfo

DOCKER_IMAGE_ENV = "ZARABAN_DOCKER_IMAGE"
_VERSION_TIMEOUT_S = 5


def gather(symbolizer: Optional[str] = None) -> EnvironmentInfo:
    """Collect the environment facts for ``report.environment`` (§12.4).

    ``symbolizer`` is the path of the ``llvm-symbolizer`` the runner found
    (``RunSettings.symbolizer``), or ``None``; §12.4 records the path, since
    that is what the runs actually use.
    """
    return EnvironmentInfo(
        os=_os_name(),
        kernel=platform.release(),
        arch=platform.machine(),
        docker_image=os.environ.get(DOCKER_IMAGE_ENV),
        python=platform.python_version(),
        gcc=tool_version("gcc"),
        clang=tool_version("clang"),
        llvm_symbolizer=symbolizer,
    )


def _os_name() -> str:
    """A readable OS name, e.g. ``Ubuntu 22.04.4 LTS``; falls back to the
    platform string when ``/etc/os-release`` is not available."""
    try:
        rel = platform.freedesktop_os_release()  # Python 3.10+
        name = rel.get("PRETTY_NAME") or rel.get("NAME")
        if name:
            return name
    except (OSError, AttributeError):
        pass
    return platform.platform()


def tool_version(name: str) -> Optional[str]:
    """The first line of ``<name> --version``, or ``None`` if the tool is not
    on PATH or does not run. Kept as a string because the report shows it to a
    person, not parses it."""
    if shutil.which(name) is None:
        return None
    try:
        result = subprocess.run([name, "--version"], capture_output=True, text=True,
                                timeout=_VERSION_TIMEOUT_S)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (result.stdout or result.stderr).strip()
    return out.splitlines()[0] if out else None
