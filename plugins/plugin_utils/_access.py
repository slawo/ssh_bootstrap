"""Remote identity and sudo capability probing."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any


SUDO_PROMPT = "__ANSIBLE_SSH_BOOTSTRAP_SUDO_PASSWORD__"
UID_PATTERN = re.compile(r"__SSH_BOOTSTRAP_UID__([0-9]+)")
USER_PATTERN = re.compile(r"__SSH_BOOTSTRAP_USER__([^\r\n]+)")
SUDO_PATTERN = re.compile(r"__SSH_BOOTSTRAP_SUDO__([01])")
BECOME_UID_PATTERN = re.compile(r"__SSH_BOOTSTRAP_BECOME_UID__([0-9]+)")

IDENTITY_COMMAND = """\
printf '__SSH_BOOTSTRAP_UID__%s\\n' "$(id -u)"
printf '__SSH_BOOTSTRAP_USER__%s\\n' "$(id -un)"
if command -v sudo >/dev/null 2>&1; then
    printf '__SSH_BOOTSTRAP_SUDO__1\\n'
else
    printf '__SSH_BOOTSTRAP_SUDO__0\\n'
fi
"""


def probe_access(run: Callable[..., dict[str, Any]], connection: dict[str, Any]) -> dict[str, Any]:
    identity = run(**connection, command=IDENTITY_COMMAND)
    if not identity.get("success") or identity.get("rc") != 0:
        return {"success": False, "reason": identity.get("reason", "identity probe failed")}
    output = identity.get("stdout", "")
    uid_match = UID_PATTERN.search(output)
    user_match = USER_PATTERN.search(output)
    sudo_match = SUDO_PATTERN.search(output)
    if not uid_match or not user_match or not sudo_match:
        return {"success": False, "reason": "identity probe returned incomplete output"}

    uid = int(uid_match.group(1))
    username = user_match.group(1)
    sudo_available = sudo_match.group(1) == "1"
    result = {
        "success": True,
        "uid": uid,
        "username": username,
        "is_root": uid == 0,
        "sudo_available": sudo_available,
        "can_become": uid == 0,
    }
    if uid == 0 or not sudo_available:
        return result

    sudo_command = (
        f"sudo -S -p '{SUDO_PROMPT}' -- sh -c "
        "'printf \"__SSH_BOOTSTRAP_BECOME_UID__%s\\n\" \"$(id -u)\"'"
    )
    sudo_result = run(
        **connection,
        command=sudo_command,
        sudo_password=connection["password"],
    )
    become_match = BECOME_UID_PATTERN.search(sudo_result.get("stdout", ""))
    result["can_become"] = bool(
        sudo_result.get("success")
        and sudo_result.get("rc") == 0
        and become_match
        and become_match.group(1) == "0"
    )
    return result
