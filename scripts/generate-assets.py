"""
Asset generation script for Stayline VPN.
Extracts the shield emblem with transparent alpha, and generates:
- assets/stayline-emblem.png (256x256 and 512x512)
- assets/stayline-logo.png (512x512)
- assets/stayline.ico (multi-resolution 16 to 256 px)
"""

import os
from collections import deque
import numpy as np
from PIL import Image

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
ASSETS_DIR = os.path.join(ROOT_DIR, "assets")
SOURCE_IMAGE = os.path.join(ASSETS_DIR, "stayline-logo-source.png")


def extract_shield_emblem(src: Image.Image) -> Image.Image:
    arr = np.array(src)
    # Shield bounding box: y in [280, 1400], x in [530, 1520]
    shield_arr = arr[280:1400, 530:1520].copy()
    sh_h, sh_w = shield_arr.shape[:2]

    # Exterior background detection
    r, g, b = shield_arr[:, :, 0], shield_arr[:, :, 1], shield_arr[:, :, 2]
    bg = (r >= 250) & (g >= 250) & (b >= 250)

    visited = np.zeros((sh_h, sh_w), dtype=bool)
    q = deque()
    for x in range(sh_w):
        if bg[0, x]:
            q.append((0, x))
            visited[0, x] = True
        if bg[sh_h - 1, x]:
            q.append((sh_h - 1, x))
            visited[sh_h - 1, x] = True
    for y in range(sh_h):
        if bg[y, 0]:
            q.append((y, 0))
            visited[y, 0] = True
        if bg[y, sh_w - 1]:
            q.append((y, sh_w - 1))
            visited[y, sh_w - 1] = True

    while q:
        y, x = q.popleft()
        for dy, dx in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
            ny, nx = y + dy, x + dx
            if 0 <= ny < sh_h and 0 <= nx < sh_w and not visited[ny, nx] and bg[ny, nx]:
                visited[ny, nx] = True
                q.append((ny, nx))

    # Make exterior background transparent
    shield_arr[visited, 3] = 0
    img = Image.fromarray(shield_arr)

    # Pad to square canvas with 8% breathing room
    max_dim = max(img.size)
    pad = int(max_dim * 0.08)
    canvas_size = max_dim + 2 * pad
    canvas = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    offset_x = (canvas_size - img.width) // 2
    offset_y = (canvas_size - img.height) // 2
    canvas.paste(img, (offset_x, offset_y))
    return canvas


def main():
    if not os.path.exists(SOURCE_IMAGE):
        raise FileNotFoundError(f"Source image not found: {SOURCE_IMAGE}")

    print(f"Loading {SOURCE_IMAGE}...")
    src = Image.open(SOURCE_IMAGE).convert("RGBA")

    print("Extracting shield emblem with transparency...")
    emblem = extract_shield_emblem(src)

    # 1. assets/stayline-emblem.png (256x256)
    out_256 = os.path.join(ASSETS_DIR, "stayline-emblem.png")
    emblem_256 = emblem.resize((256, 256), Image.Resampling.LANCZOS)
    emblem_256.save(out_256, optimize=True)
    print(f"Saved {out_256} ({os.path.getsize(out_256) / 1024:.1f} KB)")

    # 2. assets/stayline-emblem-512.png
    out_512 = os.path.join(ASSETS_DIR, "stayline-emblem-512.png")
    emblem_512 = emblem.resize((512, 512), Image.Resampling.LANCZOS)
    emblem_512.save(out_512, optimize=True)
    print(f"Saved {out_512} ({os.path.getsize(out_512) / 1024:.1f} KB)")

    # 3. assets/stayline.ico (multi-resolution 16 to 256 px)
    out_ico = os.path.join(ASSETS_DIR, "stayline.ico")
    sizes = [
        (16, 16),
        (20, 20),
        (24, 24),
        (32, 32),
        (40, 40),
        (48, 48),
        (64, 64),
        (128, 128),
        (256, 256),
    ]
    emblem.save(out_ico, sizes=sizes)
    print(f"Saved {out_ico} ({os.path.getsize(out_ico) / 1024:.1f} KB)")

    print("Asset generation complete!")


if __name__ == "__main__":
    main()
