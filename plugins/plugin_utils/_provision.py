"""Generate privileged, stdin-streamed account provisioning scripts."""

from __future__ import annotations

import re
import shlex
from typing import Any


USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_.-]*[$]?$", re.IGNORECASE)


def validate_username(username: str, option: str) -> None:
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError(f"{option} contains characters unsupported by the provisioning backends")


def build_provision_script(
    *,
    family: str,
    onboarding: dict[str, Any],
    root: dict[str, Any],
) -> str:
    username = onboarding["username"]
    password = onboarding["password"]
    validate_username(username, "onboarding.username")
    validate_username(root["username"], "root.username")
    user_q = shlex.quote(username)
    password_q = shlex.quote(password)
    root_user_q = shlex.quote(root["username"])
    root_password_q = shlex.quote(root["password"]) if root.get("password") is not None else None
    sudo_rule = (
        f"{username} ALL=(ALL:ALL) NOPASSWD: ALL"
        if onboarding["passwordless_sudo"]
        else f"{username} ALL=(ALL:ALL) ALL"
    )
    sudoers_path = f"/etc/sudoers.d/90-ansible-ssh-bootstrap-{username}"

    lines = ["set -eu"]
    if family == "openbsd":
        lines.extend(
            [
                f"if ! id {user_q} >/dev/null 2>&1; then useradd -m -s /bin/ksh {user_q}; fi",
                f"chpass -p \"$(encrypt {password_q})\" {user_q}",
            ]
        )
        if root_password_q is not None:
            lines.append(f"chpass -p \"$(encrypt {root_password_q})\" {root_user_q}")
    elif family in {"debian", "fedora", "arch"}:
        lines.extend(
            [
                f"if ! id {user_q} >/dev/null 2>&1; then useradd --create-home --shell /bin/sh {user_q}; fi",
                f"printf '%s:%s\\n' {user_q} {password_q} | chpasswd",
            ]
        )
        if root_password_q is not None:
            lines.append(f"printf '%s:%s\\n' {root_user_q} {root_password_q} | chpasswd")
    else:
        raise ValueError(f"unsupported provisioning family: {family}")

    lines.extend(
        [
            "umask 077",
            f"sudoers_tmp=$(mktemp {shlex.quote(sudoers_path)}.XXXXXX)",
            f"printf '%s\\n' {shlex.quote(sudo_rule)} > \"$sudoers_tmp\"",
            "chmod 0440 \"$sudoers_tmp\"",
            "visudo -cf \"$sudoers_tmp\" >/dev/null",
            f"mv \"$sudoers_tmp\" {shlex.quote(sudoers_path)}",
            "printf '__SSH_BOOTSTRAP_PROVISIONED__1\\n'",
        ]
    )
    return "\n".join(lines) + "\n"
