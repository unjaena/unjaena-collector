from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceFormat:
    artifact_type: str
    label: str
    family: str
    extensions: tuple[str, ...]
    patterns: tuple[str, ...]


SOURCE_FORMATS: tuple[SourceFormat, ...] = (
    SourceFormat(
        artifact_type="e01_image",
        label="E01 / Ex01 / L01 image",
        family="Forensic image",
        extensions=(".e01", ".ex01", ".l01", ".lx01", ".s01"),
        patterns=("*.E[0-9][0-9]", "*.e[0-9][0-9]", "*.L[0-9][0-9]", "*.l[0-9][0-9]", "*.S[0-9][0-9]", "*.s[0-9][0-9]", "*.Ex01", "*.ex01", "*.Lx01", "*.lx01"),
    ),
    SourceFormat(
        artifact_type="raw_image",
        label="DD / RAW / IMG image",
        family="Raw image",
        extensions=(".dd", ".raw", ".img", ".bin", ".001", ".000"),
        patterns=("*.dd", "*.raw", "*.img", "*.bin", "*.00[0-9]", "*.0[0-9][0-9]"),
    ),
    SourceFormat(
        artifact_type="forensic_container_image",
        label="AFF / AFF4 / AD1 image",
        family="Forensic image",
        extensions=(".aff", ".afd", ".afm", ".aff4", ".ad1"),
        patterns=("*.aff", "*.afd", "*.afm", "*.aff4", "*.ad1"),
    ),
    SourceFormat(
        artifact_type="virtual_disk_image",
        label="Virtual disk image",
        family="Virtual disk",
        extensions=(".vmdk", ".vdi", ".vhd", ".vhdx", ".qcow2", ".qed", ".hdd", ".vpc"),
        patterns=("*.vmdk", "*.vdi", "*.vhd", "*.vhdx", "*.qcow2", "*.qed", "*.hdd", "*.vpc"),
    ),
    SourceFormat(
        artifact_type="filesystem_image",
        label="Filesystem volume image",
        family="Filesystem volume",
        extensions=(".ntfs", ".fat", ".fat12", ".fat16", ".fat32", ".exfat", ".ext", ".ext2", ".ext3", ".ext4", ".xfs", ".btrfs", ".hfs", ".hfsx", ".apfs", ".ufs"),
        patterns=("*.ntfs", "*.fat", "*.fat12", "*.fat16", "*.fat32", "*.exfat", "*.ext", "*.ext2", "*.ext3", "*.ext4", "*.xfs", "*.btrfs", "*.hfs", "*.hfsx", "*.apfs", "*.ufs"),
    ),
    SourceFormat(
        artifact_type="optical_disk_image",
        label="ISO / DMG image",
        family="Optical or macOS image",
        extensions=(".iso", ".dmg", ".cdr"),
        patterns=("*.iso", "*.ISO", "*.dmg", "*.DMG", "*.cdr", "*.CDR"),
    ),
    SourceFormat(
        artifact_type="mobile_ffs_bundle",
        label="Mobile or logical bundle",
        family="Bundle",
        extensions=(".zip", ".tar", ".tgz", ".gz", ".7z"),
        patterns=("*.zip", "*.tar", "*.tgz", "*.tar.gz", "*.gz", "*.7z"),
    ),
)

SPEC_BY_ARTIFACT = {item.artifact_type: item for item in SOURCE_FORMATS}
SOURCE_TYPE_OPTIONS = tuple((item.label, item.artifact_type) for item in SOURCE_FORMATS)


def source_file_filter() -> str:
    exts = []
    for item in SOURCE_FORMATS:
        exts.extend(f"*{ext}" for ext in item.extensions)
    unique_exts = sorted(set(exts), key=str.lower)
    return f"Supported evidence sources ({' '.join(unique_exts)});;All Files (*)"


SOURCE_FILE_FILTER = source_file_filter()


def candidate_artifacts_for_path(path: Path) -> tuple[str, ...]:
    name = path.name
    lower = name.lower()
    suffix = path.suffix.lower()
    matches: list[str] = []
    for item in SOURCE_FORMATS:
        if suffix in item.extensions or any(fnmatch.fnmatch(lower, pattern.lower()) for pattern in item.patterns):
            matches.append(item.artifact_type)
    return tuple(dict.fromkeys(matches))


def classify_source_path(path: Path, forced_artifact_type: str | None = None) -> SourceFormat | None:
    if forced_artifact_type:
        return SPEC_BY_ARTIFACT.get(forced_artifact_type)
    candidates = candidate_artifacts_for_path(path)
    if not candidates:
        return None
    return SPEC_BY_ARTIFACT.get(candidates[0])


def format_file_size(path: Path) -> str:
    try:
        size = float(path.stat().st_size)
    except OSError:
        return "unknown size"
    units = ("B", "KB", "MB", "GB", "TB")
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.1f} {units[idx]}"


def supported_format_summary() -> str:
    return "E01/Ex01/L01, DD/RAW/IMG, AFF/AFF4/AD1, VMDK/VDI/VHD/VHDX/QCOW2, ISO/DMG, NTFS/FAT/exFAT/ext/HFS/APFS volume images, ZIP/TAR bundles"
