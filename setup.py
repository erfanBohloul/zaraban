"""Shim for tools that still call setup.py. All metadata, including the
version (read from zaraban/__init__.py), is in pyproject.toml."""

from setuptools import setup

setup()
