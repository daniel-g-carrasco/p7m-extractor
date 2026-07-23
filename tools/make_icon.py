#!/usr/bin/env python3
"""Generate assets/icon.ico and assets/icon.png (requires Pillow).

Drawn at high resolution and downscaled, so every size stays crisp.
Design: white document with a folded corner on a blue rounded tile,
with a red wax-seal-and-ribbon badge (the digital-signature motif).
"""

from pathlib import Path

from PIL import Image, ImageDraw

S = 1024  # master canvas, downscaled at the end

BLUE = (26, 95, 180, 255)        # tile
BLUE_DARK = (16, 62, 120, 255)   # fold shadow
WHITE = (255, 255, 255, 255)
PAPER_LINE = (160, 175, 195, 255)
RED = (192, 28, 40, 255)         # seal
RED_DARK = (140, 18, 28, 255)    # ribbon


def main() -> None:
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

    out = Path(__file__).resolve().parent.parent / "assets"
    out.mkdir(exist_ok=True)
    master = img.resize((256, 256), Image.LANCZOS)
    master.save(out / "icon.png")
    master.save(
        out / "icon.ico",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
               (64, 64), (128, 128), (256, 256)],
    )
    print(f"written: {out / 'icon.ico'} and icon.png")


if __name__ == "__main__":
    main()
