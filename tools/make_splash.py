#!/usr/bin/env python3
"""Generate assets/splash.png, the start-up splash of the Windows build
(requires Pillow). PyInstaller shows it right after launch, before Python
and GTK are loaded; the status line ("Avvio in corso…") is drawn by
PyInstaller itself at the text_pos given in p7m-extractor.spec, so leave
that area empty here.
"""

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_icon import render_master  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
W, H = 400, 150
BG = (250, 250, 250, 255)
BORDER = (200, 200, 205, 255)
TITLE = (36, 31, 49, 255)
SUBTITLE = (94, 92, 100, 255)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    names = ["segoeuib.ttf", "DejaVuSans-Bold.ttf"] if bold else ["segoeui.ttf", "DejaVuSans.ttf"]
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size)


def main() -> None:
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, W - 1, H - 1), radius=12, fill=BG, outline=BORDER)

    icon = render_master().resize((96, 96), Image.LANCZOS)
    img.alpha_composite(icon, (24, (H - 96) // 2))

    d.text((140, 34), "P7M Extractor", font=font(24, bold=True), fill=TITLE)
    d.text((141, 70), "Estrazione di documenti firmati .p7m", font=font(13), fill=SUBTITLE)
    # y ≈ 110-125 is reserved for PyInstaller's status text (text_pos in the spec)

    out = ROOT / "assets" / "splash.png"
    img.save(out)
    print(f"written: {out.relative_to(ROOT)} ({W}x{H})")


if __name__ == "__main__":
    main()
