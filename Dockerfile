# Zaraban: isolated Linux x86_64 test environment (course spec §2, §5; SPEC §14.5)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Toolchains and analysis tools
#   gcc/g++            release builds (project's own hardening flags)
#   clang, llvm, lld   sanitized builds, llvm-symbolizer, llvm-cov/llvm-profdata (execution trace)
#   universal-ctags    function ranges for linking findings to the diff (SPEC §9.2)
#   gdb, valgrind      manual debugging only; the tool does not depend on them
#   checksec, file     manual cross-check of the tool's hardening and ELF checks
# Network fallback: every download is tried DIRECTLY first. Only if that
# fails and BUILD_PROXY is set (from .env, see .env.example) is it retried
# through that proxy, for example your VPN's local HTTP proxy. The proxy is
# used only while building; it is not kept in the image.
ARG BUILD_PROXY=""

RUN set -eu; \
    PKGS="build-essential gcc g++ clang llvm lld universal-ctags gdb valgrind \
          binutils file checksec bsdextrautils git make cmake pkg-config \
          python3 python3-pip python3-venv python3-dev ca-certificates curl"; \
    direct() { \
        apt-get -o Acquire::http::Timeout=15 -o Acquire::Retries=1 update \
        && apt-get -o Acquire::http::Timeout=15 install -y --no-install-recommends $PKGS; }; \
    viaproxy() { \
        P="-o Acquire::http::Proxy=$BUILD_PROXY -o Acquire::https::Proxy=$BUILD_PROXY"; \
        apt-get $P update && apt-get $P install -y --no-install-recommends $PKGS; }; \
    if ! direct; then \
        if [ -z "$BUILD_PROXY" ]; then \
            echo "ERROR: direct download failed and BUILD_PROXY is not set (see .env.example)" >&2; exit 1; \
        fi; \
        echo ">>> Direct download failed; retrying through BUILD_PROXY=$BUILD_PROXY" >&2; \
        rm -rf /var/lib/apt/lists/*; viaproxy; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# Python dependencies come from pyproject.toml, the single source of truth.
# Only pyproject.toml is copied, so this layer is rebuilt only when dependencies
# change. The package itself is uninstalled again: the live code is used from
# the bind-mounted /workspace through PYTHONPATH.
COPY pyproject.toml /tmp/deps/pyproject.toml
# pip and setuptools are upgraded first: Ubuntu 22.04's pip 22.0 ignores the
# [project] table and would install a package called "UNKNOWN" with no
# dependencies at all. pyproject.toml reads the version from
# zaraban.__version__, so the stub package defines one (any value: it is
# uninstalled again at the end of this step).
RUN set -eu; \
    pipi() { \
        python3 -m pip install --timeout 15 --retries 1 "$@" && return 0; \
        [ -n "$BUILD_PROXY" ] || { echo "ERROR: pip failed and BUILD_PROXY is not set" >&2; return 1; }; \
        echo ">>> pip failed directly; retrying through BUILD_PROXY=$BUILD_PROXY" >&2; \
        HTTP_PROXY="$BUILD_PROXY" HTTPS_PROXY="$BUILD_PROXY" python3 -m pip install "$@"; }; \
    pipi --upgrade "pip>=24" "setuptools>=68" wheel; \
    cd /tmp/deps; \
    mkdir zaraban; touch README.md; \
    echo '__version__ = "0.0.0"' > zaraban/__init__.py; \
    pipi ".[dev]"; \
    python3 -m pip uninstall -y zaraban; \
    rm -rf /tmp/deps

# Fail the build early if a tool the pipeline relies on is missing
RUN gcc --version >/dev/null \
    && clang --version >/dev/null \
    && llvm-symbolizer --version >/dev/null \
    && llvm-cov --version >/dev/null \
    && llvm-profdata merge --help >/dev/null \
    && ctags --version | grep -q "Universal Ctags" \
    && git --version >/dev/null \
    && python3 -c "import yaml, pydantic, elftools, unidiff, rich, pytest"

# Run as a non-root user (SPEC §14.5). On Linux hosts, pass your own ids so
# files written to the bind mount belong to you:
#   UID=$(id -u) GID=$(id -g) docker compose build
ARG USER_UID=1000
ARG USER_GID=1000
RUN groupadd -o -g "${USER_GID}" zaraban \
    && useradd -o -m -u "${USER_UID}" -g "${USER_GID}" -s /bin/bash zaraban

# Sanitizer defaults for MANUAL runs inside the container (for example when
# reproducing a CVE by hand). The tool itself never inherits these: it builds
# a clean environment for every run and sets its own options (SPEC §7.2).
ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer \
    ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:disable_coredump=1 \
    UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1:symbolize=1 \
    PYTHONPATH=/workspace

USER zaraban
WORKDIR /workspace

CMD ["/bin/bash"]
