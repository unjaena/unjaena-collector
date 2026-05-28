from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

class ContainerKind(Enum):
    APP_DATA = 'app_data'
    APP_GROUP = 'app_group'
    APP_BUNDLE = 'app_bundle'
    SYSTEM = 'system'
    ROOT_SYSTEM = 'root_system'
    USER_MEDIA = 'user_media'

@dataclass(frozen=True)
class AndroidArtifactSpec:
    artifact_type: str
    package: str
    relative_path: str
    container_kind: ContainerKind = ContainerKind.APP_DATA
    description: str = ''
    is_directory: bool = False
    child_suffix_filter: Tuple[str, ...] = ()
    filename_globs: Tuple[str, ...] = ()
    @property
    def full_path_pattern(self) -> str:
        if self.container_kind == ContainerKind.APP_DATA:
            return f'data/data/{self.package}/{self.relative_path}'
        return self.relative_path

@dataclass(frozen=True)
class IOSArtifactSpec:
    artifact_type: str
    package: Optional[str]
    relative_path: str
    container_kind: ContainerKind = ContainerKind.APP_DATA
    description: str = ''
    is_directory: bool = False
    pull_sqlite_sidecars: bool = False
    child_suffix_filter: Tuple[str, ...] = ()

ANDROID_PATH_SPECS: Tuple[AndroidArtifactSpec, ...] = ()
IOS_PATH_SPECS: Tuple[IOSArtifactSpec, ...] = ()

def all_android_specs() -> List[AndroidArtifactSpec]:
    return list(ANDROID_PATH_SPECS)

def all_ios_specs() -> List[IOSArtifactSpec]:
    return list(IOS_PATH_SPECS)

def find_android_spec_by_path(zip_entry_path: str) -> Optional[AndroidArtifactSpec]:
    rel = zip_entry_path[len('Dump/'):] if zip_entry_path.startswith('Dump/') else zip_entry_path
    for spec in ANDROID_PATH_SPECS:
        if rel == spec.full_path_pattern:
            return spec
    return None

def find_ios_system_spec_by_path(zip_entry_path: str) -> Optional[IOSArtifactSpec]:
    rel = zip_entry_path[len('filesystem1/'):] if zip_entry_path.startswith('filesystem1/') else zip_entry_path
    for spec in IOS_PATH_SPECS:
        if spec.container_kind not in (ContainerKind.SYSTEM, ContainerKind.ROOT_SYSTEM):
            continue
        if rel == spec.relative_path:
            return spec
    return None

def all_artifact_types() -> List[str]:
    types = [s.artifact_type for s in ANDROID_PATH_SPECS]
    types.extend(s.artifact_type for s in IOS_PATH_SPECS)
    return types
