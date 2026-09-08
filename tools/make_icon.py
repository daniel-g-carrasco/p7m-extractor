#!/usr/bin/env python3
"""Generate the raster application icons (requires Pillow):

  assets/icon.ico, assets/icon.png            Windows exe / installer icon
  data/icons/hicolor/<N>x<N>/apps/<APP_ID>.png icon-theme PNGs (64, 128, 256)
  installer/wizard-small-<dpi>.bmp             Inno Setup wizard header image
  installer/wizard-large-<dpi>.bmp             Inno Setup finish-page image

Drawn at high resolution and downscaled, so every size stays crisp.
Design: white document with a folded corner on a blue rounded tile,
with a red wax-seal-and-ribbon badge (the digital-signature motif).
The scalable version of the same design lives in
data/icons/hicolor/scalable/apps/<APP_ID>.svg.
"""

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
APP_ID = "io.github.daniel_g_carrasco.p7m_extractor"

S = 1024  # master canvas, downscaled at the end

BLUE = (26, 95, 180, 255)        # tile
BLUE_DARK = (16, 62, 120, 255)   # fold shadow
WHITE = (255, 255, 255, 255)
PAPER_LINE = (160, 175, 195, 255)
RED = (192, 28, 40, 255)         # seal
RED_DARK = (140, 18, 28, 255)    # ribbon


def render_master() -> Image.Image:
    """Return the icon as a 1024x1024 RGBA image."""
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # blue rounded tile
    d.rounded_rectangle((64, 64, S - 64, S - 64), radius=180, fill=BLUE)

    # document sheet with folded top-right corner
    sx0, sy0, sx1, sy1 = 280, 200, 744, 824
    fold = 120
    d.polygon(
        [(sx0, sy0), (sx1 - fold, sy0), (sx1, sy0 + fold),
         (sx1, sy1), (sx0, sy1)],
        fill=WHITE,
    )
    d.polygon(
        [(sx1 - fold, sy0), (sx1 - fold, sy0 + fold), (sx1, sy0 + fold)],
        fill=BLUE_DARK,
    )

    # text lines on the sheet
    for i, y in enumerate(range(sy0 + 130, sy0 + 420, 72)):
        d.rounded_rectangle(
            (sx0 + 70, y, sx1 - 70 - (60 if i % 2 else 0), y + 30),
            radius=15, fill=PAPER_LINE,
        )

    # ribbon tails, then wax seal on top
    cx, cy, r = 660, 760, 150
    d.polygon([(cx - 60, cy + 40), (cx - 150, cy + 250),
               (cx - 30, cy + 200), (cx, cy + 80)], fill=RED_DARK)
    d.polygon([(cx + 60, cy + 40), (cx + 150, cy + 250),
               (cx + 30, cy + 200), (cx, cy + 80)], fill=RED_DARK)
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=RED)
    d.ellipse((cx - r + 34, cy - r + 34, cx + r - 34, cy + r - 34),
              outline=WHITE, width=18)
    # check mark inside the seal
    d.line([(cx - 62, cy + 4), (cx - 14, cy + 52), (cx + 66, cy - 46)],
           fill=WHITE, width=30, joint="curve")
    return img


def main() -> None:
    img = render_master()

    out = ROOT / "assets"
    out.mkdir(exist_ok=True)
    master = img.resize((256, 256), Image.LANCZOS)
    master.save(out / "icon.png")
    master.save(
        out / "icon.ico",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
               (64, 64), (128, 128), (256, 256)],
    )
    print(f"written: {out / 'icon.ico'} and icon.png")

    for size in (64, 128, 256):
        dest = ROOT / "data" / "icons" / "hicolor" / f"{size}x{size}" / "apps" / f"{APP_ID}.png"
        dest.parent.mkdir(parents=True, exist_ok=True)
        img.resize((size, size), Image.LANCZOS).save(dest)
        print(f"written: {dest.relative_to(ROOT)}")

    # Inno Setup wizard bitmaps (24-bit BMP, white background), one per DPI
    # scale; the sizes are the ones documented for WizardSmallImageFile and
    # WizardImageFile. Setup picks the closest match at run time.
    small = {100: (55, 58), 125: (64, 68), 150: (83, 80), 175: (92, 97),
             200: (110, 106), 225: (119, 123), 250: (138, 140)}
    large = {100: (164, 314), 125: (192, 386), 150: (246, 459), 175: (273, 556),
             200: (328, 604), 225: (355, 700), 250: (410, 797)}
    for kind, sizes in (("small", small), ("large", large)):
        for dpi, (w, h) in sizes.items():
            canvas = Image.new("RGBA", (w, h), WHITE)
            side = min(w, h) - 6 if kind == "small" else int(w * 0.62)
            icon = img.resize((side, side), Image.LANCZOS)
            y = (h - side) // 2 if kind == "small" else int(h * 0.18)
            canvas.alpha_composite(icon, ((w - side) // 2, y))
            dest = ROOT / "installer" / f"wizard-{kind}-{dpi}.bmp"
            canvas.convert("RGB").save(dest, format="BMP")
        print(f"written: installer/wizard-{kind}-<dpi>.bmp ({len(sizes)} sizes)")


if __name__ == "__main__":
    main()
