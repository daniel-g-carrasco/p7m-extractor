#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The PNG sizes of the app icon, from the scalable one in
data/icons/hicolor/scalable/apps (drawn as make_ico.py draws: GdkPixbuf
in a GTK app, Qt in a Qt app; no Pillow):

  data/icons/hicolor/<N>x<N>/apps/<APP_ID>.png   for N in 64, 128, 256
  site/icon.png                                   the 256 one, for the site and the Flatpak page

    python3 tools/make_icons.py

The scalable SVG is the master: edit it, run this, commit both. It needs
tools/make_ico.py next to it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_ico import ROOT, icon_paths, identity, render_png  # noqa: E402

SIZES = (64, 128, 256)


def main(root: Path = ROOT) -> int:
    root = Path(root)
    app_id = identity(root)["APP_ID"]
    svg, _small = icon_paths(root)
    for size in SIZES:
        png = render_png(svg, size)
        out = root / "data" / "icons" / "hicolor" / f"{size}x{size}" / "apps" / f"{app_id}.png"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(png)
        print(out.relative_to(root))
        if size == 256 and (root / "site").is_dir():
            (root / "site" / "icon.png").write_bytes(png)
            print("site/icon.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
