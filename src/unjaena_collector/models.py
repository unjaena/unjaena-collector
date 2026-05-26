from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuthSession:
    session_id: str
    case_id: str
    collection_token: str
    server_url: str
    signing_key: str | None = None


@dataclass
class ProfileTarget:
    artifact_type: str
    kind: str
    patterns: list[str]
    max_bytes: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectionProfile:
    profile_id: str
    case_id: str
    expires_at: str
    targets: list[ProfileTarget]
    upload_mode: str = "r2_presigned"
    signature: str | None = None
