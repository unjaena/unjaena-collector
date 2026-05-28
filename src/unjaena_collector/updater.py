from __future__ import annotations

import json
import platform
import re
import urllib.request
import webbrowser
from dataclasses import dataclass
from typing import Any

from . import __version__

LATEST_RELEASE_URL = "https://api.github.com/repos/unjaena/unjaena-collector/releases/latest"
RELEASE_PAGE_URL = "https://github.com/unjaena/unjaena-collector/releases/latest"


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    url: str
    size: int = 0


@dataclass(frozen=True)
class UpdateInfo:
    current_version: str
    latest_version: str
    release_url: str
    asset: ReleaseAsset | None

    @property
    def available(self) -> bool:
        return _version_tuple(self.latest_version) > _version_tuple(self.current_version)


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value or "")
    return tuple(int(part) for part in parts[:4]) or (0,)


def normalize_tag(tag: str) -> str:
    value = tag.strip()
    for prefix in ("unjaena-collector-v", "unJaena-collector-v", "collector-v", "v"):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def _asset_priority(system: str, machine: str) -> list[str]:
    system = system.lower()
    machine = machine.lower()
    if system == "windows":
        return ["windows-amd64.exe", "windows-x64.exe", "windows-amd64.zip", "windows-x64.zip"]
    if system == "darwin":
        arch = "arm64" if machine in {"arm64", "aarch64"} else "x86_64"
        alt = "x64" if arch == "x86_64" else arch
        return [f"darwin-{arch}.dmg", f"macos-{arch}.dmg", f"darwin-{alt}.dmg", f"macos-{alt}.dmg", f"darwin-{arch}.tar.gz", f"macos-{arch}.tar.gz"]
    if system == "linux":
        return ["linux-x86_64.tar.gz", "linux-amd64.tar.gz", "linux-x64.tar.gz"]
    return []


def select_asset(assets: list[dict[str, Any]], system: str | None = None, machine: str | None = None) -> ReleaseAsset | None:
    system = system or platform.system()
    machine = machine or platform.machine()
    priorities = _asset_priority(system, machine)
    normalized = [(str(item.get("name") or ""), str(item.get("browser_download_url") or ""), int(item.get("size") or 0)) for item in assets]
    for pattern in priorities:
        for name, url, size in normalized:
            if pattern in name and url:
                return ReleaseAsset(name=name, url=url, size=size)
    for name, url, size in normalized:
        if name and url and not name.startswith("SHA256SUMS"):
            return ReleaseAsset(name=name, url=url, size=size)
    return None


def parse_release(payload: dict[str, Any], current_version: str = __version__) -> UpdateInfo:
    latest = normalize_tag(str(payload.get("tag_name") or ""))
    return UpdateInfo(
        current_version=current_version,
        latest_version=latest,
        release_url=str(payload.get("html_url") or RELEASE_PAGE_URL),
        asset=select_asset(list(payload.get("assets") or [])),
    )


def check_for_update(current_version: str = __version__, timeout: int = 5) -> UpdateInfo:
    request = urllib.request.Request(
        LATEST_RELEASE_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "unJaena-Collector"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return parse_release(payload, current_version=current_version)


def open_update(info: UpdateInfo) -> bool:
    target = info.asset.url if info.asset else info.release_url
    return bool(webbrowser.open(target))
