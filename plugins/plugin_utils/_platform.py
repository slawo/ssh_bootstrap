"""Remote platform detection and package-manager strategy."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any


SYSTEM_PATTERN = re.compile(r"__SSH_BOOTSTRAP_SYSTEM__([^\r\n]+)")
ID_PATTERN = re.compile(r"__SSH_BOOTSTRAP_ID__([^\r\n]*)")
ID_LIKE_PATTERN = re.compile(r"__SSH_BOOTSTRAP_ID_LIKE__([^\r\n]*)")

DETECT_COMMAND = """\
printf '__SSH_BOOTSTRAP_SYSTEM__%s\\n' "$(uname -s)"
platform_id=''
platform_like=''
if [ -r /etc/os-release ]; then
    . /etc/os-release
    platform_id=${ID:-}
    platform_like=${ID_LIKE:-}
fi
printf '__SSH_BOOTSTRAP_ID__%s\\n' "$platform_id"
printf '__SSH_BOOTSTRAP_ID_LIKE__%s\\n' "$platform_like"
"""

SUDO_INSTALL_COMMANDS = {
    "apt": "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y sudo",
    "dnf": "dnf install -y sudo",
    "pacman": "pacman --sync --refresh --sysupgrade --noconfirm && pacman --sync --noconfirm sudo",
    "pkg_add": "pkg_add sudo",
}


def parse_platform(output: str) -> dict[str, str]:
    system_match = SYSTEM_PATTERN.search(output)
    platform_match = ID_PATTERN.search(output)
    like_match = ID_LIKE_PATTERN.search(output)
    if not system_match or not platform_match or not like_match:
        raise ValueError("platform probe returned incomplete output")

    system = system_match.group(1).strip().lower()
    platform_id = platform_match.group(1).strip().lower()
    id_like = like_match.group(1).strip().lower().split()
    family = ""
    package_manager = ""
    if system == "openbsd":
        family, package_manager = "openbsd", "pkg_add"
    elif platform_id in {"debian", "ubuntu", "armbian"} or {"debian", "ubuntu"}.intersection(id_like):
        family, package_manager = "debian", "apt"
    elif platform_id == "fedora" or "fedora" in id_like:
        family, package_manager = "fedora", "dnf"
    elif platform_id == "arch" or "arch" in id_like:
        family, package_manager = "arch", "pacman"
    else:
        raise ValueError(f"unsupported platform: system={system or 'unknown'}, id={platform_id or 'unknown'}")
    return {
        "system": system,
        "id": platform_id,
        "family": family,
        "package_manager": package_manager,
    }


def detect_platform(run: Callable[..., dict[str, Any]], connection: dict[str, Any]) -> dict[str, Any]:
    probe = run(**connection, command=DETECT_COMMAND)
    if not probe.get("success") or probe.get("rc") != 0:
        return {"success": False, "reason": probe.get("reason", "platform probe failed")}
    try:
        platform = parse_platform(probe.get("stdout", ""))
    except ValueError as exc:
        return {"success": False, "reason": str(exc)}
    return {"success": True, **platform}


def sudo_install_command(platform: dict[str, str]) -> str:
    try:
        return SUDO_INSTALL_COMMANDS[platform["package_manager"]]
    except KeyError as exc:
        raise ValueError("no sudo installation strategy for detected platform") from exc
