"""A signed file on disk extracted next to itself, and the .p7m files of
the folders given.
"""

from __future__ import annotations

from pathlib import Path

from p7m_extractor.core.names import _strip_p7m
from p7m_extractor.data.cms import BerError, decode_container, extract_econtent

_CHUNK = 1 << 20  # 1 MiB: I/O granularity for progress reporting


def extract_file(src: Path, overwrite: bool = False, progress=None) -> tuple[Path, int]:
    """Extract src next to itself. Return (dest, signature_layers).

    Nested envelopes (file.pdf.p7m.p7m) are unwrapped in a single pass.
    progress(fraction), if given, is called with values from 0.0 to 1.0
    while the source is read (first half) and the output written (second
    half): large files on network shares can take a while.
    Raises FileExistsError when dest exists and overwrite is False,
    BerError for unsupported/corrupt input, OSError on I/O problems.
    """
    src = Path(src)
    size = max(src.stat().st_size, 1)
    raw = bytearray()
    with open(src, "rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            raw += chunk
            if progress:
                progress(0.5 * min(len(raw), size) / size)
    content = extract_econtent(decode_container(bytes(raw)))
    name = _strip_p7m(src.name)
    layers = 1
    while True:
        try:
            content = extract_econtent(decode_container(content))
        except BerError:
            break
        layers += 1
        name = _strip_p7m(name)
    dest = src.with_name(name)
    if dest.exists() and not overwrite:
        raise FileExistsError(str(dest))
    total = max(len(content), 1)
    with open(dest, "wb") as out:
        for i in range(0, len(content), _CHUNK):
            out.write(content[i:i + _CHUNK])
            if progress:
                progress(0.5 + 0.5 * min(i + _CHUNK, total) / total)
    if progress:
        progress(1.0)
    return dest, layers


def iter_p7m(paths) -> list[Path]:
    """Expand files/folders into a flat list of .p7m files (folders: recursive)."""
    found: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            found.extend(sorted(
                x for x in p.rglob("*")
                if x.is_file() and x.suffix.lower() == ".p7m"
            ))
        elif p.is_file():
            found.append(p)
    return found
