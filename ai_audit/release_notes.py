"""Per-version release notes extracted from CHANGELOG.md."""

from __future__ import annotations

import re


def notes_for_version(text: str, version: str) -> str:
    """Return the markdown body of the ``## v<version>`` section, if present."""
    heading = re.compile(rf"^##\s+v?{re.escape(version.strip().lstrip('v'))}\b.*$", re.M)
    match = heading.search(text)
    if not match:
        return ""
    start = match.end()
    nxt = re.compile(r"^##\s+", re.M).search(text, start)
    return text[start : nxt.start() if nxt else len(text)].strip("\n")
