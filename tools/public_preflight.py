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
    r'\bClaude\b', r'\bCopilot\b', r'\bAider\b',
    r'\bOllama\b', r'LM Studio', r'HuggingFace', r'Continue\.dev',
    r'MCP server grants', r'conversation logs', r'tool-call records', r'model fingerprints',
]

def main() -> int:
    failures = []
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in PATTERNS]
    for path in ROOT.rglob('*'):
        if any(part in SKIP for part in path.parts):
            continue
        if not path.is_file() or path == Path(__file__).resolve():
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
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
