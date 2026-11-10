"""What the extracted file is called."""

from __future__ import annotations


def _strip_p7m(name: str) -> str:
    return name[:-4] if name.lower().endswith(".p7m") and len(name) > 4 else name + ".out"
