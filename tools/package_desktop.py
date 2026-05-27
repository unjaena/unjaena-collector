import platform
import shutil
import subprocess
import tarfile
import tempfile
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


def _copy_docs(target_dir: Path) -> None:
    shutil.copy2(ROOT / "README.md", target_dir / "README.md")
    shutil.copy2(ROOT / "SECURITY.md", target_dir / "SECURITY.md")


def _package_windows(release: Path, base: str) -> None:
    exe = ROOT / "dist" / "UnjaenaCollector.exe"
    if not exe.exists():
        raise SystemExit(f"Missing desktop build: {exe}")
    direct = release / f"{base}.exe"
    shutil.copy2(exe, direct)
    zip_target = release / f"{base}.zip"
    with zipfile.ZipFile(zip_target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(exe, "UnjaenaCollector.exe")
        zf.write(ROOT / "README.md", "README.md")
        zf.write(ROOT / "SECURITY.md", "SECURITY.md")
    print(direct)
    print(zip_target)


def _package_macos(release: Path, base: str) -> None:
    app = ROOT / "dist" / "UnjaenaCollector.app"
    if not app.exists():
        app = ROOT / "dist" / "UnjaenaCollector"
    if not app.exists():
        raise SystemExit(f"Missing desktop build: {app}")
    tar_target = release / f"{base}.tar.gz"
    with tarfile.open(tar_target, "w:gz") as tf:
        tf.add(app, app.name)
        tf.add(ROOT / "README.md", "README.md")
        tf.add(ROOT / "SECURITY.md", "SECURITY.md")
    print(tar_target)
    if app.suffix == ".app" and shutil.which("hdiutil"):
        dmg_target = release / f"{base}.dmg"
        with tempfile.TemporaryDirectory() as temp:
            staging = Path(temp) / "unJaena Collector"
            staging.mkdir()
            shutil.copytree(app, staging / app.name, symlinks=True)
            _copy_docs(staging)
            result = subprocess.run([
                "hdiutil", "create", "-volname", "unJaena Collector", "-srcfolder", str(staging),
                "-ov", "-format", "UDZO", str(dmg_target),
            ], cwd=ROOT, text=True, capture_output=True)
            if result.returncode != 0:
                raise SystemExit((result.stdout + result.stderr).strip())
        print(dmg_target)


def _package_unix(release: Path, base: str) -> None:
    exe = ROOT / "dist" / "UnjaenaCollector"
    if not exe.exists():
        raise SystemExit(f"Missing desktop build: {exe}")
    tar_target = release / f"{base}.tar.gz"
    with tarfile.open(tar_target, "w:gz") as tf:
        tf.add(exe, "UnjaenaCollector")
        tf.add(ROOT / "README.md", "README.md")
        tf.add(ROOT / "SECURITY.md", "SECURITY.md")
    print(tar_target)


def main() -> int:
    version = _version()
    release = ROOT / "release"
    release.mkdir(exist_ok=True)
    base = _asset_name(version)
    system = platform.system().lower()
    if system == "windows":
        _package_windows(release, base)
    elif system == "darwin":
        _package_macos(release, base)
    else:
        _package_unix(release, base)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
