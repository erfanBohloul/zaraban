"""Unified Git Diff Parser for Zaraban.

Parses unified diff format to extract modified files, line ranges,
hunk details, and modified function names.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import re


@dataclass
class DiffHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    function_header: Optional[str] = None
    added_lines: list[int] = field(default_factory=list)      # Line numbers in patched file
    removed_lines: list[int] = field(default_factory=list)    # Line numbers in base file
    raw_text: str = ""

    def contains_new_line(self, line_num: int) -> bool:
        """Check if a line number in the patched file falls within this hunk."""
        return self.new_start <= line_num <= (self.new_start + max(1, self.new_count) - 1)

    def contains_old_line(self, line_num: int) -> bool:
        """Check if a line number in the base file falls within this hunk."""
        return self.old_start <= line_num <= (self.old_start + max(1, self.old_count) - 1)


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    hunks: list[DiffHunk] = field(default_factory=list)
    modified_functions: set[str] = field(default_factory=set)

    @property
    def filename(self) -> str:
        """Normalized base filename (e.g. main.c)."""
        target = self.new_path if self.new_path != "/dev/null" else self.old_path
        return Path(target).name


@dataclass
class PatchDiff:
    files: list[FileDiff] = field(default_factory=list)
    raw_diff: str = ""

    def get_file(self, filename: str) -> Optional[FileDiff]:
        """Find FileDiff by filename or partial path."""
        target_name = Path(filename).name
        for f in self.files:
            if f.filename == target_name or filename in f.new_path or filename in f.old_path:
                return f
        return None

    @property
    def all_modified_functions(self) -> set[str]:
        funcs = set()
        for f in self.files:
            funcs.update(f.modified_functions)
        return funcs


class DiffParser:
    """Parses unified diff strings or files."""

    HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
    FUNC_NAME_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")

    @classmethod
    def parse_file(cls, diff_path: str | Path) -> PatchDiff:
        p = Path(diff_path)
        if not p.is_file():
            raise FileNotFoundError(f"Diff file not found: {diff_path}")
        return cls.parse_string(p.read_text(encoding="utf-8", errors="replace"))

    @classmethod
    def parse_string(cls, diff_text: str) -> PatchDiff:
        lines = diff_text.splitlines()
        files: list[FileDiff] = []
        current_file: Optional[FileDiff] = None
        current_hunk: Optional[DiffHunk] = None

        new_curr_line = 0
        old_curr_line = 0

        for line in lines:
            if line.startswith("--- "):
                # Start of old file
                old_p = line[4:].strip().split("\t")[0]
                if old_p.startswith("a/"):
                    old_p = old_p[2:]
                current_file = FileDiff(old_path=old_p, new_path="")
                files.append(current_file)
                current_hunk = None
            elif line.startswith("+++ "):
                new_p = line[4:].strip().split("\t")[0]
                if new_p.startswith("b/"):
                    new_p = new_p[2:]
                if current_file:
                    current_file.new_path = new_p
            elif line.startswith("@@ "):
                m = cls.HUNK_HEADER_RE.match(line)
                if m and current_file:
                    old_start = int(m.group(1))
                    old_count = int(m.group(2)) if m.group(2) else 1
                    new_start = int(m.group(3))
                    new_count = int(m.group(4)) if m.group(4) else 1
                    header_tail = m.group(5).strip()

                    fn_match = cls.FUNC_NAME_RE.search(header_tail)
                    func_name = fn_match.group(1) if fn_match else None
                    if func_name:
                        current_file.modified_functions.add(func_name)

                    current_hunk = DiffHunk(
                        old_start=old_start,
                        old_count=old_count,
                        new_start=new_start,
                        new_count=new_count,
                        function_header=func_name,
                        raw_text=line + "\n"
                    )
                    current_file.hunks.append(current_hunk)
                    old_curr_line = old_start
                    new_curr_line = new_start
            elif current_hunk:
                current_hunk.raw_text += line + "\n"
                if line.startswith("+"):
                    current_hunk.added_lines.append(new_curr_line)
                    new_curr_line += 1
                elif line.startswith("-"):
                    current_hunk.removed_lines.append(old_curr_line)
                    old_curr_line += 1
                elif line.startswith(" "):
                    old_curr_line += 1
                    new_curr_line += 1

        return PatchDiff(files=files, raw_diff=diff_text)
