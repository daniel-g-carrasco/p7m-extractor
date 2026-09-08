#!/usr/bin/env python3
"""Generate the start-up splash of the Windows build (requires Pillow):

  assets/splash.png        light variant (GTK "Default" light palette)
  assets/splash-dark.png   dark variant  (GTK "Default" dark palette)

PyInstaller shows the light PNG right after launch, before Python and GTK
are loaded; p7m-extractor.spec extends its Tcl script so that the dark PNG
is swapped in when Windows "Apps mode" is dark. The status line ("Avvio in
corso…") is drawn by PyInstaller itself at the text_pos given in the spec,
so leave that area empty here.

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

# GTK "Default" theme palettes, so the splash matches the app window
PALETTES = {
    "splash.png": {            # light
        "bg": (246, 245, 244, 255),       # #f6f5f4
        "border": (205, 199, 194, 255),   # #cdc7c2
        "title": (46, 52, 54, 255),       # #2e3436
        "subtitle": (136, 139, 140, 255),  # fg at 55% over bg
    },
    "splash-dark.png": {       # dark
        "bg": (53, 53, 53, 255),          # #353535
        "border": (27, 27, 27, 255),      # #1b1b1b
        "title": (238, 238, 236, 255),    # #eeeeec
        "subtitle": (155, 155, 153, 255),  # fg at 55% over bg
    },
}


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


def render(palette: dict, icon: Image.Image) -> Image.Image:
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, W - 1, H - 1), radius=px(12), fill=palette["bg"],
                        outline=palette["border"], width=max(1, px(1)))
    img.alpha_composite(icon, (px(24), (H - px(96)) // 2))
    d.text((px(140), px(34)), "P7M Extractor", font=font(24, bold=True),
           fill=palette["title"])
    d.text((px(141), px(70)), "Estrazione di documenti firmati .p7m",
           font=font(13), fill=palette["subtitle"])
    # y ≈ 110-125 (unscaled) is reserved for PyInstaller's status text
    return img


def main() -> None:
    icon = render_master().resize((px(96), px(96)), Image.LANCZOS)
    for name, palette in PALETTES.items():
        out = ROOT / "assets" / name
        render(palette, icon).save(out)
        print(f"written: {out.relative_to(ROOT)} ({W}x{H}, scale {K})")


if __name__ == "__main__":
    main()
