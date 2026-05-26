import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = [
    r"[\uac00-\ud7af]",
    r"AI-DF",
    r"ai-df",
    r"chimborazo",
    r"migration/backend",
    r"/workspace/AI-DF",
    r"C:\\project\\AI-DF",
    r"runpod",
    r"forensic_admin",
    r"secret",
    r"private key",
    r"access token",
    r"refresh token",
    r"credential.*extract",
    r"extract.*credential",
    r"password.*extract",
    r"extract.*password",
]
SKIP = {".git", "__pycache__", ".pytest_cache", "dist", "build"}


def main() -> int:
    failures = []
    compiled = [re.compile(p, re.IGNORECASE) for p in PATTERNS]
    for path in ROOT.rglob("*"):
        if any(part in SKIP for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path == Path(__file__).resolve():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for pattern in compiled:
            if pattern.search(text):
                failures.append(f"{path.relative_to(ROOT)}: {pattern.pattern}")
    if failures:
        print("Public preflight failed")
        for item in failures:
            print(item)
        return 1
    print("Public preflight passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
