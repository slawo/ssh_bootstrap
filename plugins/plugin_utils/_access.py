"""Remote identity and native privilege-escalation probing."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any


SUDO_PROMPT = "__ANSIBLE_SSH_BOOTSTRAP_SUDO_PASSWORD__"
UID_PATTERN = re.compile(r"__SSH_BOOTSTRAP_UID__([0-9]+)")
USER_PATTERN = re.compile(r"__SSH_BOOTSTRAP_USER__([^\r\n]+)")
METHOD_PATTERN = re.compile(r"__SSH_BOOTSTRAP_METHOD__(sudo|doas|none)")
BECOME_UID_PATTERN = re.compile(r"__SSH_BOOTSTRAP_BECOME_UID__([0-9]+)")

IDENTITY_COMMAND = """\
printf '__SSH_BOOTSTRAP_UID__%s\\n' "$(id -u)"
printf '__SSH_BOOTSTRAP_USER__%s\\n' "$(id -un)"
if test "$(uname -s)" = OpenBSD && command -v doas >/dev/null 2>&1; then
    printf '__SSH_BOOTSTRAP_METHOD__doas\\n'
elif command -v sudo >/dev/null 2>&1; then
    printf '__SSH_BOOTSTRAP_METHOD__sudo\\n'
elif command -v doas >/dev/null 2>&1; then
    printf '__SSH_BOOTSTRAP_METHOD__doas\\n'
else
    printf '__SSH_BOOTSTRAP_METHOD__none\\n'
fi
"""


def probe_access(run: Callable[..., dict[str, Any]], connection: dict[str, Any]) -> dict[str, Any]:
    identity = run(**connection, command=IDENTITY_COMMAND)
    if not identity.get("success") or identity.get("rc") != 0:
        return {"success": False, "reason": identity.get("reason", "identity probe failed")}
    output = identity.get("stdout", "")
    uid_match = UID_PATTERN.search(output)
    user_match = USER_PATTERN.search(output)
    method_match = METHOD_PATTERN.search(output)
    if not uid_match or not user_match or not method_match:
        return {"success": False, "reason": "identity probe returned incomplete output"}

    uid = int(uid_match.group(1))
    method = method_match.group(1)
    available = method != "none"
    result = {
        "success": True,
        "uid": uid,
        "username": user_match.group(1),
        "is_root": uid == 0,
        "sudo_available": available,
        "escalation_available": available,
        "become_method": None if uid == 0 else method if available else None,
        "can_become": uid == 0,
    }
    if uid == 0 or not available:
        return result

    prefix = f"sudo -S -p '{SUDO_PROMPT}' --" if method == "sudo" else "doas"
    command = f"{prefix} sh -c 'printf \"__SSH_BOOTSTRAP_BECOME_UID__%s\\n\" \"$(id -u)\"'"
    elevated = run(**connection, command=command, sudo_password=connection["password"])
    become_match = BECOME_UID_PATTERN.search(elevated.get("stdout", ""))
    result["can_become"] = bool(
        elevated.get("success")
        and elevated.get("rc") == 0
        and become_match
        and become_match.group(1) == "0"
    )
    return result
