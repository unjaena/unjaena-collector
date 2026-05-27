import platform
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]["version"]


def _asset_name(version: str) -> str:
    system = platform.system().lower() or "unknown"
    machine = platform.machine().lower() or "unknown"
    return f"unjaena-collector-desktop-{version}-{system}-{machine}"


def main() -> int:
    version = _version()
    release = ROOT / "release"
    release.mkdir(exist_ok=True)
    system = platform.system().lower()
    if system == "windows":
        exe_name = "UnjaenaCollector.exe"
        app = ROOT / "dist" / exe_name
    elif system == "darwin":
        app = ROOT / "dist" / "UnjaenaCollector.app"
        exe_name = "UnjaenaCollector.app"
        if not app.exists():
            app = ROOT / "dist" / "UnjaenaCollector"
            exe_name = "UnjaenaCollector"
    else:
        exe_name = "UnjaenaCollector"
        app = ROOT / "dist" / exe_name
    if not app.exists():
        raise SystemExit(f"Missing desktop build: {app}")
    base = _asset_name(version)
    if system == "windows":
        target = release / f"{base}.zip"
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(app, exe_name)
            zf.write(ROOT / "README.md", "README.md")
            zf.write(ROOT / "SECURITY.md", "SECURITY.md")
    else:
        target = release / f"{base}.tar.gz"
        with tarfile.open(target, "w:gz") as tf:
            tf.add(app, exe_name)
            tf.add(ROOT / "README.md", "README.md")
            tf.add(ROOT / "SECURITY.md", "SECURITY.md")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
