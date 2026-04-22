"""Render a 30-second terminal-style demo GIF for the README hero banner.

Uses PIL/Pillow to synthesize each frame from scratch (no real terminal
needed), so the output is reproducible across machines and free of any
personal environment details.

Scenario:
  $ git clone ... unjaena-collector
  $ cd unjaena-collector
  $ pip install -r requirements.txt
      ✓ 42 packages installed
  $ python run.py --platform windows --output ./evidence
      [████████░░░░░░] 55%  Collecting MFT...
      [██████████████] 100% 11 Tier S artifacts detected
      ✓ Hash manifest written
      ✓ Encrypted upload to app.unjaena.com
      ✓ Analysis ready (case #abc123)

Output: collector/docs/readme-demo.gif
Size:   900 x 520 pixels, ~32 frames @ 800ms each (total ~26s)

Run from repo root:
  python collector/docs/make_readme_demo_gif.py
"""
from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# ── Terminal palette (GitHub dark theme) ──────────────────────
BG        = (13, 17, 23)          # #0d1117
FG        = (201, 209, 217)       # #c9d1d9
GREEN     = (63, 185, 80)         # #3fb950
BLUE      = (88, 166, 255)        # #58a6ff
YELLOW    = (210, 153, 34)        # #d29922
RED       = (248, 81, 73)         # #f85149
GREY      = (125, 133, 144)       # #7d8590
CURSOR    = (88, 166, 255)

# Macbook-style window chrome
CHROME_H  = 28
BUTTON_R  = 6
BTN_RED   = (255, 95, 86)
BTN_YEL   = (255, 189, 46)
BTN_GRN   = (39, 201, 63)

# Frame geometry
W, H      = 900, 520
MARGIN_X  = 20
LINE_H    = 22
FONT_SIZE = 15

FONT_PATH = "C:/Windows/Fonts/CascadiaMono.ttf"


def _load_font(size: int) -> ImageFont.FreeTypeFont:
    try:
        return ImageFont.truetype(FONT_PATH, size)
    except OSError:
        return ImageFont.load_default()


FONT = _load_font(FONT_SIZE)
FONT_SMALL = _load_font(12)


def _base_frame() -> Image.Image:
    """Canvas with window chrome (macOS-style traffic lights + title)."""
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    # Chrome bar
    draw.rectangle([0, 0, W, CHROME_H], fill=(27, 31, 36))
    # Traffic lights
    for i, color in enumerate([BTN_RED, BTN_YEL, BTN_GRN]):
        x = 14 + i * 20
        y = CHROME_H // 2
        draw.ellipse([x - BUTTON_R, y - BUTTON_R, x + BUTTON_R, y + BUTTON_R],
                     fill=color)
    # Title
    draw.text((W // 2 - 105, 7), "unjaena-collector  —  demo",
              font=FONT_SMALL, fill=GREY)
    return img


def _render_lines(lines, cursor: bool = False) -> Image.Image:
    """Render a list of (color, text) tuples as terminal lines."""
    img = _base_frame()
    draw = ImageDraw.Draw(img)
    y = CHROME_H + 16

    for line in lines:
        if line is None:
            y += LINE_H
            continue
        if isinstance(line, tuple):
            color, text = line
        else:
            color, text = FG, line
        # Simple word-level colored tokens via prefix markers
        draw.text((MARGIN_X, y), text, font=FONT, fill=color)
        y += LINE_H

    if cursor:
        # Blinking block cursor
        draw.rectangle([MARGIN_X + 8 * 11, y - LINE_H + 4,
                        MARGIN_X + 8 * 11 + 10, y - LINE_H + 20],
                       fill=CURSOR)
    return img


def _progress_bar(percent: int, label: str) -> str:
    filled = int(percent * 20 / 100)
    bar = "█" * filled + "░" * (20 - filled)
    return f"  [{bar}] {percent:>3d}%  {label}"


# ── Scenario frames ───────────────────────────────────────────
frames: list[Image.Image] = []

# Helper: make line tuples
def _prompt(cmd: str = "") -> tuple:
    return (GREEN, f"investigator@laptop:~/work$ {cmd}")


# Frame 1-3: Window opens
for _ in range(2):
    frames.append(_render_lines([(GREY, "")]))

# Frame 4: prompt appears
frames.append(_render_lines([_prompt("")], cursor=True))

# Frame 5: typing git clone
frames.append(_render_lines([
    _prompt("git clone https://github.com/unjaena/unjaena-collector"),
], cursor=True))

# Frame 6: git clone output
frames.append(_render_lines([
    _prompt("git clone https://github.com/unjaena/unjaena-collector"),
    (GREY, "Cloning into 'unjaena-collector'..."),
    (GREY, "remote: Enumerating objects: 2847, done."),
    (GREY, "Receiving objects: 100% (2847/2847), 8.3 MiB | 12 MiB/s"),
]))

# Frame 7: cd + pip
frames.append(_render_lines([
    _prompt("git clone https://github.com/unjaena/unjaena-collector"),
    (GREY, "✓ cloned (2847 files, 8.3 MiB)"),
    None,
    _prompt("cd unjaena-collector"),
    _prompt("pip install -r requirements.txt"),
], cursor=True))

# Frame 8: pip install progress
for pct, msg in [(20, "PyQt6"), (45, "pymobiledevice3"), (70, "blackboxprotobuf"),
                 (90, "ccl-chromium-reader"), (100, "42 packages")]:
    frames.append(_render_lines([
        _prompt("pip install -r requirements.txt"),
        (BLUE, _progress_bar(pct, f"Installing  {msg}")),
    ]))

# Frame 14: install done
frames.append(_render_lines([
    _prompt("pip install -r requirements.txt"),
    (GREEN, "  ✓ 42 packages installed"),
    None,
    _prompt("python run.py --platform windows --output ./evidence"),
], cursor=True))

# Frame 15-20: collection progress
progress_steps = [
    (10,  "Prefetch (124 files)"),
    (25,  "Registry hives (NTUSER, SOFTWARE, SYSTEM)"),
    (45,  "Event logs (Security, Sysmon, Defender MPLog)"),
    (62,  "Teams v2 LevelDB cache"),
    (80,  "OneDrive sync log (.odl records)"),
    (100, "11 Tier S artifacts detected"),
]
for pct, msg in progress_steps:
    color = GREEN if pct == 100 else BLUE
    frames.append(_render_lines([
        _prompt("python run.py --platform windows --output ./evidence"),
        (GREY, "  Launching collector ..."),
        (color, _progress_bar(pct, msg)),
    ]))

# Frame 21: hash manifest
frames.append(_render_lines([
    _prompt("python run.py --platform windows --output ./evidence"),
    (GREY, "  Launching collector ..."),
    (GREEN, "  [████████████████████] 100%  11 Tier S artifacts detected"),
    None,
    (GREEN, "  ✓ SHA-256 hash manifest written (evidence/manifest.sha256)"),
]))

# Frame 22: upload
frames.append(_render_lines([
    _prompt("python run.py --platform windows --output ./evidence"),
    (GREY, "  Launching collector ..."),
    (GREEN, "  [████████████████████] 100%  11 Tier S artifacts detected"),
    None,
    (GREEN, "  ✓ SHA-256 hash manifest written"),
    (BLUE, "  ↗ Encrypted upload to app.unjaena.com"),
]))

# Frame 23: done
frames.append(_render_lines([
    _prompt("python run.py --platform windows --output ./evidence"),
    (GREEN, "  ✓ 11 Tier S artifacts detected"),
    (GREEN, "  ✓ SHA-256 hash manifest written"),
    (GREEN, "  ✓ Encrypted upload complete"),
    None,
    (YELLOW, "  → Case ready:  https://app.unjaena.com/cases/abc123"),
    (YELLOW, "  → 4-language AI report (KR / EN / JA / ZH)"),
]))

# Frames 24-27: linger on final state so viewer can read
for _ in range(4):
    frames.append(frames[-1].copy())

# Save as animated GIF
out_dir = Path("collector/docs")
out_dir.mkdir(exist_ok=True, parents=True)
out_path = out_dir / "readme-demo.gif"

# Frame durations: typing=200ms, install=400ms, collection=500ms, final linger=1500ms
durations = (
    [300] * 3                               # window open
    + [400] * 3                             # git clone
    + [400] * 1                             # cd + pip
    + [300] * 5                             # pip progress
    + [600] * 1                             # install done
    + [500] * 6                             # collection progress
    + [700] * 2                             # hash + upload
    + [1200] * 1                            # done screen
    + [1500] * 4                            # linger
)
# Pad or trim to match frame count
while len(durations) < len(frames):
    durations.append(800)
durations = durations[:len(frames)]

frames[0].save(
    out_path,
    save_all=True,
    append_images=frames[1:],
    duration=durations,
    loop=0,
    optimize=True,
)

print(f"✓ GIF written: {out_path}")
print(f"  Size: {W}x{H}  Frames: {len(frames)}  Duration: {sum(durations)/1000:.1f}s")
