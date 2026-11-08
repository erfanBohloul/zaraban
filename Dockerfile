# Linux x86_64 environment required by project specification
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install C/C++ toolchain, sanitizers, binary inspection tools, and python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    clang \
    llvm \
    lld \
    gdb \
    binutils \
    git \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    cmake \
    pkg-config \
    file \
    checksec \
    valgrind \
    bsdextrautils \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies for Zaraban
RUN pip3 install --no-cache-dir \
    pyyaml \
    pydantic \
    pyelftools \
    unidiff \
    rich \
    pytest

# Set up working directory
WORKDIR /workspace

# Set default LLVM symbolizer path for ASan stack traces
ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
ENV ASAN_OPTIONS=symbolize=1:detect_leaks=0:abort_on_error=1
ENV UBSAN_OPTIONS=symbolize=1:print_stacktrace=1:halt_on_error=1

# By default launch an interactive bash shell or zaraban CLI
CMD ["/bin/bash"]
