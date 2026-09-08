#!/usr/bin/env python3
"""Generate assets/splash.png, the start-up splash of the Windows build
(requires Pillow). PyInstaller shows it right after launch, before Python
and GTK are loaded; the status line ("Avvio in corso…") is drawn by
PyInstaller itself at the text_pos given in p7m-extractor.spec, so leave
that area empty here.

The exe is per-monitor DPI aware, so the image is shown pixel for pixel on
every screen: it is rendered at 1.5x (600x225) as a compromise between
100% and 200% display scaling.
"""

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_icon import render_master  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
K = 1.5                      # render scale; text_pos in the spec follows it
W, H = int(400 * K), int(150 * K)
BG = (250, 250, 250, 255)
BORDER = (200, 200, 205, 255)
TITLE = (36, 31, 49, 255)
SUBTITLE = (94, 92, 100, 255)


def px(v: float) -> int:
    return int(round(v * K))


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    names = ["segoeuib.ttf", "DejaVuSans-Bold.ttf"] if bold else ["segoeui.ttf", "DejaVuSans.ttf"]
    for name in names:
        try:
            return ImageFont.truetype(name, px(size))
        except OSError:
            continue
    return ImageFont.load_default(px(size))


def main() -> None:
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, W - 1, H - 1), radius=px(12), fill=BG,
                        outline=BORDER, width=max(1, px(1)))

    icon = render_master().resize((px(96), px(96)), Image.LANCZOS)
    img.alpha_composite(icon, (px(24), (H - px(96)) // 2))

    d.text((px(140), px(34)), "P7M Extractor", font=font(24, bold=True), fill=TITLE)
    d.text((px(141), px(70)), "Estrazione di documenti firmati .p7m",
           font=font(13), fill=SUBTITLE)
    # y ≈ 110-125 (unscaled) is reserved for PyInstaller's status text

    out = ROOT / "assets" / "splash.png"
    img.save(out)
    print(f"written: {out.relative_to(ROOT)} ({W}x{H}, scale {K})")


if __name__ == "__main__":
    main()
