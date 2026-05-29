#!/usr/bin/env python3
from __future__ import annotations
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', '__pycache__', '.pytest_cache', 'dist', 'build'}
PATTERNS = [
    r'[\uac00-\ud7af]', r'AI-DF', r'chimborazo', r'runpod', r'forensic_admin',
    r'private key', r'access token', r'refresh token', r'github_pat_',
    r'Login Data', r'IndexedDB', r'security question', r'Kakao', r'WhatsApp',
    r'claude\.ai', r'chatgpt', r'\.codex',
]

def read_text(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ('utf-8', 'utf-8-sig', 'utf-16'):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return ''

def main() -> int:
    failures = []
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in PATTERNS]
    for path in ROOT.rglob('*'):
        if any(part in SKIP for part in path.parts):
            continue
        if not path.is_file() or path == Path(__file__).resolve():
            continue
        text = read_text(path)
        if not text:
            continue
        for pattern in compiled:
            if pattern.search(text):
                failures.append(f'{path.relative_to(ROOT)}: {pattern}')
    if failures:
        print('Public preflight failed')
        for failure in failures:
            print(failure)
        return 1
    print('Public preflight passed')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
