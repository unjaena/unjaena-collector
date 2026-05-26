from pathlib import Path
import subprocess
import sys


def test_public_preflight_passes():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "tools" / "public_preflight.py")], cwd=root, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
