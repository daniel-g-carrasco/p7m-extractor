"""Keep only the loader formats used by the application's icons."""

from pathlib import Path
from runpy import run_path

import PyInstaller


def hook(hook_api):
    upstream = Path(PyInstaller.__file__).parent / "hooks" / Path(__file__).name
    upstream_hook = run_path(str(upstream))["hook"]
    collect_loaders = upstream_hook.__globals__["_collect_loaders"]

    def icon_loaders(libdir):
        return [path for path in collect_loaders(libdir) if Path(path).name in (
            "pixbufloader_svg.dll", "libpixbufloader-png.dll",
        )]

    # Filter before PyInstaller scans DLL dependencies and writes loaders.cache.
    upstream_hook.__globals__["_collect_loaders"] = icon_loaders
    upstream_hook(hook_api)
