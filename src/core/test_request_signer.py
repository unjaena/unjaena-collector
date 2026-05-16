from __future__ import annotations

import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SRC_DIR = HERE.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def test_canonical_json_bytes_are_stable_for_signing():
    from core.request_signer import canonical_json_bytes

    left = {"b": 2, "a": {"z": True, "k": "value"}}
    right = {"a": {"k": "value", "z": True}, "b": 2}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_json_bytes(left) == b'{"a":{"k":"value","z":true},"b":2}'
