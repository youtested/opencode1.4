"""Unified diff create/apply (pure Python).

Used by the edit tool and permission dialogs. Produces/consumes standard
`--- a/<path>` / `+++ b/<path>` unified diffs compatible with `patch`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_HEADER_RE = re.compile(r"^--- a/(.*)$")
_HEADER2_RE = re.compile(r"^\+\+\+ b/(.*)$")


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    hunks: list[list[str]] = field(default_factory=list)

    @property
    def text(self) -> str:
        lines = [f"--- a/{self.old_path}", f"+++ b/{self.new_path}"]
        for hunk in self.hunks:
            lines.extend(hunk)
        return "\n".join(lines) + "\n"




def parse_diff(diff_text: str) -> list[FileDiff]:
    """Parse a unified diff into one FileDiff per file."""
    lines = diff_text.splitlines(keepends=True)
    files: list[FileDiff] = []
    current: FileDiff | None = None
    current_hunk: list[str] = []

    def flush_hunk() -> None:
        nonlocal current_hunk
        if current is not None and current_hunk:
            current.hunks.append(current_hunk)
        current_hunk = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip("\n")
        # A file header is the PAIR `--- a/x` followed by `+++ b/y`. Requiring
        # both is what lets a multi-file patch parse: the old `and current is
        # None` guard kept the first FileDiff forever, so the second file's
        # hunks (header lines included) were appended to the first and applying
        # it wrote one file's lines into the other. Content lines that merely
        # start with "--- " cannot be mistaken for a header this way.
        if (
            stripped.startswith("--- a/")
            and i + 1 < len(lines)
            and lines[i + 1].rstrip("\n").startswith("+++ b/")
        ):
            flush_hunk()
            current = FileDiff(
                old_path=stripped[6:], new_path=lines[i + 1].rstrip("\n")[6:]
            )
            files.append(current)
            i += 2
            continue
        if stripped.startswith("@@") and current is not None:
            flush_hunk()
        if current is not None:
            current_hunk.append(line)
        i += 1
    flush_hunk()
    return files




