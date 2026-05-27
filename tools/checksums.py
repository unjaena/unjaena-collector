import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release"


def main() -> int:
    RELEASE.mkdir(exist_ok=True)
    assets = sorted(p for p in RELEASE.iterdir() if p.is_file() and not p.name.startswith("SHA256SUMS"))
    if not assets:
        raise SystemExit("No release assets found")
    lines = []
    for path in assets:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    suffix = "-".join(path.stem for path in assets[:1])[:80] or "assets"
    target = RELEASE / f"SHA256SUMS-{suffix}.txt"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
