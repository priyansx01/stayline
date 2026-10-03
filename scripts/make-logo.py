"""
Draws the stayline logo (two-tone shield with a padlock) from geometry and
writes every logo asset, so the mark stays crisp at any size:

- assets/stayline-logo.svg               vector master
- assets/stayline-logo-512.png           large PNG (README, website)
- assets/stayline.ico                    app/installer icon, 16 to 256 px
- crates/tray/ui/icons/stayline-emblem.png  in-app emblem (256 px)

    python scripts/make-logo.py
"""

import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLUE = (30, 99, 180)
TEAL = (31, 154, 160)
WHITE = (255, 255, 255)
N = 1024  # design grid; everything below is in these units


def cubic(p0, p1, p2, p3, steps=64):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        pts.append(
            (
                u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0],
                u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1],
            )
        )
    return pts


# Right half of the shield as cubic segments; the left half is mirrored.
TOP = (512, 84)
SHOULDER = (868, 196)
TIP = (512, 948)
TOP_CURVE = ((626, 150), (750, 184))
SIDE_CURVE = ((884, 540), (770, 800))


def shield_polygon():
    right = cubic(TOP, *TOP_CURVE, SHOULDER) + cubic(SHOULDER, *SIDE_CURVE, TIP)[1:]
    left = [(N - x, y) for x, y in reversed(right[:-1])]
    return right + left


# Padlock
BODY = (348, 468, 676, 744)  # x0, y0, x1, y1
BODY_R = 52
SHACKLE_CX, SHACKLE_TOP, SHACKLE_R, SHACKLE_W = 512, 268, 112, 58
KEY_CY, KEY_R = 582, 44
KEY_STEM = (512 - 22, 600, 512 + 22, 680)


def draw(scale: int) -> Image.Image:
    """Renders the logo at N*scale pixels (scale for supersampling)."""
    s = scale
    size = N * s
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    # Two-tone shield: draw the shield as a mask, colour each half.
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).polygon([(x * s, y * s) for x, y in shield_polygon()], fill=255)
    halves = Image.new("RGBA", (size, size), BLUE + (255,))
    ImageDraw.Draw(halves).rectangle((size // 2, 0, size, size), fill=TEAL + (255,))
    img.paste(halves, (0, 0), mask)

    d = ImageDraw.Draw(img)
    # Shackle: a U made of a half ring and two legs reaching into the body.
    r_out = (SHACKLE_R + SHACKLE_W / 2) * s
    cy = (SHACKLE_TOP + SHACKLE_R) * s
    cx = SHACKLE_CX * s
    d.arc(
        (cx - r_out, cy - r_out, cx + r_out, cy + r_out),
        180,
        360,
        fill=WHITE,
        width=int(SHACKLE_W * s),
    )
    for leg_x in (SHACKLE_CX - SHACKLE_R, SHACKLE_CX + SHACKLE_R):
        x0 = (leg_x - SHACKLE_W / 2) * s
        d.rectangle((x0, cy, x0 + SHACKLE_W * s, (BODY[1] + 20) * s), fill=WHITE)

    # Body
    d.rounded_rectangle([v * s for v in BODY], radius=BODY_R * s, fill=WHITE)

    # Keyhole cut back out in the shield colours.
    hole = Image.new("L", (size, size), 0)
    hd = ImageDraw.Draw(hole)
    hd.ellipse(((512 - KEY_R) * s, (KEY_CY - KEY_R) * s, (512 + KEY_R) * s, (KEY_CY + KEY_R) * s), fill=255)
    hd.rounded_rectangle([v * s for v in KEY_STEM], radius=12 * s, fill=255)
    img.paste(halves, (0, 0), hole)
    return img


def svg() -> str:
    def path_d():
        r = [TOP, *TOP_CURVE, SHOULDER, *SIDE_CURVE, TIP]
        m = lambda p: f"{N - p[0]:.0f} {p[1]:.0f}"
        q = lambda p: f"{p[0]:.0f} {p[1]:.0f}"
        return (
            f"M{q(r[0])} C{q(r[1])} {q(r[2])} {q(r[3])} C{q(r[4])} {q(r[5])} {q(r[6])} "
            f"C{m(r[5])} {m(r[4])} {m(r[3])} C{m(r[2])} {m(r[1])} {m(r[0])} Z"
        )

    bx0, by0, bx1, by1 = BODY
    sx0, sx1 = SHACKLE_CX - SHACKLE_R, SHACKLE_CX + SHACKLE_R
    sy = SHACKLE_TOP + SHACKLE_R
    kx0, ky0, kx1, ky1 = KEY_STEM
    blue = "#%02x%02x%02x" % BLUE
    teal = "#%02x%02x%02x" % TEAL
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {N} {N}">
  <defs>
    <clipPath id="shield"><path d="{path_d()}"/></clipPath>
    <clipPath id="keyhole">
      <circle cx="512" cy="{KEY_CY}" r="{KEY_R}"/>
      <rect x="{kx0}" y="{ky0}" width="{kx1 - kx0}" height="{ky1 - ky0}" rx="12"/>
    </clipPath>
  </defs>
  <g clip-path="url(#shield)">
    <rect width="512" height="{N}" fill="{blue}"/>
    <rect x="512" width="512" height="{N}" fill="{teal}"/>
  </g>
  <path d="M{sx0} {by0 + 20} V{sy} A{SHACKLE_R} {SHACKLE_R} 0 0 1 {sx1} {sy} V{by0 + 20}" fill="none" stroke="#fff" stroke-width="{SHACKLE_W}"/>
  <rect x="{bx0}" y="{by0}" width="{bx1 - bx0}" height="{by1 - by0}" rx="{BODY_R}" fill="#fff"/>
  <g clip-path="url(#keyhole)">
    <rect width="512" height="{N}" fill="{blue}"/>
    <rect x="512" width="512" height="{N}" fill="{teal}"/>
  </g>
</svg>
"""


def main():
    master = draw(scale=2).resize((N, N), Image.Resampling.LANCZOS)

    def at(px):
        return master.resize((px, px), Image.Resampling.LANCZOS)

    with open(os.path.join(ROOT, "assets", "stayline-logo.svg"), "w", newline="\n") as f:
        f.write(svg())
    at(512).save(os.path.join(ROOT, "assets", "stayline-logo-512.png"), optimize=True)
    at(256).save(os.path.join(ROOT, "crates", "tray", "ui", "icons", "stayline-emblem.png"), optimize=True)
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    at(256).save(os.path.join(ROOT, "assets", "stayline.ico"), sizes=[(s, s) for s in sizes])
    print("wrote assets/stayline-logo.svg, stayline-logo-512.png, stayline.ico and the in-app emblem")


if __name__ == "__main__":
    main()
