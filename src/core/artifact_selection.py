"""Non-visual collection-scope state for the collector UI."""

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping


SUPPORTED_ARTIFACT_CATEGORIES = frozenset(
    {"windows", "android", "ios", "linux", "macos", "ai_activity"}
)


@dataclass(slots=True)
class ArtifactSelection:
    """Selection and availability state for one collector artifact type."""

    artifact_type: str
    category: str
    checked: bool = False
    enabled: bool = False
    availability_reason: str = ""


class ArtifactSelectionModel:
    """Own artifact selection without coupling collection logic to widgets."""

    def __init__(self, registry: Mapping[str, Mapping[str, object]]):
        self._items: Dict[str, ArtifactSelection] = {}
        self.include_deleted = True

        self.replace_registry(registry)

    def replace_registry(self, registry: Mapping[str, Mapping[str, object]]) -> None:
        """Rebuild selection state after an authenticated runtime profile update."""
        items: Dict[str, ArtifactSelection] = {}

        for artifact_type, info in registry.items():
            category = str(info.get("category") or "windows")
            if category not in SUPPORTED_ARTIFACT_CATEGORIES:
                continue
            if artifact_type.startswith("mobile_") and "category" not in info:
                continue
            items[artifact_type] = ArtifactSelection(
                artifact_type=artifact_type,
                category=category,
            )

        self._items = items

    @property
    def items(self) -> Dict[str, ArtifactSelection]:
        return self._items

    def selected_types(self) -> list[str]:
        return [
            artifact_type
            for artifact_type, item in self._items.items()
            if item.checked
        ]

    def checked_count(self) -> int:
        return sum(1 for item in self._items.values() if item.checked)

    def enabled_count(self) -> int:
        return sum(1 for item in self._items.values() if item.enabled)

    def any_selected(self) -> bool:
        return any(item.checked for item in self._items.values())

    def set_enabled_types(self, artifact_types: Iterable[str]) -> None:
        enabled = set(artifact_types)
        for artifact_type, item in self._items.items():
            item.enabled = artifact_type in enabled
            if not item.enabled:
                item.checked = False
