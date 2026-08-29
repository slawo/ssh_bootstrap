# Copyright: (c) 2026, cluster-setup maintainers
# MIT License
"""Discover working SSH credentials before Ansible can connect to a host."""

from __future__ import annotations

import re
import shlex
from typing import Any

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    import pexpect
except ImportError:  # pragma: no cover - exercised on controllers without pexpect
    pexpect = None


SUCCESS_MARKER = "__ANSIBLE_SSH_BOOTSTRAP_OK__"
DEFAULT_PROMPTS = {
    "login_password": r"(?i)(?:password|passphrase)\s*:\s*$",
    "current_password": r"(?i)\(?current\)?(?:\s+unix)?\s+password\s*:\s*$",
    "new_password": (
        r"(?i)(?:(?:enter\s+)?new(?:\s+unix)?\s+password|"
        r"create\s+(?:root|user(?:\s+\([^)]+\))?)\s+password)\s*:\s*$"
    ),
    "repeat_password": r"(?i)(?:retype|repeat|confirm)(?:\s+new)?(?:\s+(?:root|user(?:\s+\([^)]+\))?))?\s+password\s*:\s*$",
    "new_username": (
        r"(?i)(?:please\s+)?(?:provide|enter|create|choose)(?:\s+(?:a|new))?\s+"
        r"user(?:name)?(?:\s+\([^\r\n]*\))?\s*:\s*$"
    ),
    "ignored_name": r"(?i)(?<!user)(?<!user )\bname\s*:\s*$",
    "permission_denied": r"(?i)permission denied|authentication failed",
    "host_key_error": r"(?i)host key verification failed|remote host identification has changed",
    "success": re.escape(SUCCESS_MARKER),
}


def _validated_credentials(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise AnsibleActionFail("credentials must be a non-empty list")

    result = []
    for index, candidate in enumerate(value):
        if not isinstance(candidate, dict):
            raise AnsibleActionFail(f"credentials[{index}] must be a dictionary")
        username = candidate.get("username")
        password = candidate.get("password")
        if not isinstance(username, str) or not username:
            raise AnsibleActionFail(f"credentials[{index}].username must be a non-empty string")
        if not isinstance(password, str):
            raise AnsibleActionFail(f"credentials[{index}].password must be a string")
        result.append({"username": username, "password": password})
    return result


def _ssh_command(host: str, port: int, username: str, host_key_checking: str) -> list[str]:
    return [
        "ssh",
        "-tt",
        "-p",
        str(port),
        "-o",
        "BatchMode=no",
        "-o",
        "PreferredAuthentications=keyboard-interactive,password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        f"StrictHostKeyChecking={host_key_checking}",
        "-o",
        "LogLevel=ERROR",
        "--",
        f"{username}@{host}",
        "sh",
        "-c",
        shlex.quote(f"printf '{SUCCESS_MARKER}\\n'"),
    ]


def _attempt(
    command: list[str],
    candidate: dict[str, str],
    onboarding: dict[str, Any],
    prompts: dict[str, str],
    timeout: int,
    debug: bool = False,
) -> dict[str, Any]:
    child = pexpect.spawn(command[0], command[1:], encoding="utf-8", timeout=timeout, echo=False)
    patterns = [
        prompts["success"],
        prompts["current_password"],
        prompts["new_password"],
        prompts["repeat_password"],
        prompts["new_username"],
        prompts["ignored_name"],
        prompts["login_password"],
        prompts["permission_denied"],
        prompts["host_key_error"],
        pexpect.EOF,
        pexpect.TIMEOUT,
    ]
    authenticated = False
    changed = False
    login_password_sent = False
    onboarding_seen = False
    pending_password_change = False
    pending_created_user_password = False
    active_password_kind: str | None = None
    password_changed = False
    created_user = False
    transcript: list[str] = []

    def outcome(**values: Any) -> dict[str, Any]:
        if password_changed:
            values["password_changed"] = True
        if created_user:
            values["created_user"] = True
        if debug:
            session = "".join(transcript)
            secrets = [candidate["password"], onboarding.get("password"), onboarding.get("user_password")]
            for secret in secrets:
                if isinstance(secret, str) and secret:
                    session = session.replace(secret, "********")
            values["session"] = session
        return values

    try:
        for _unused in range(20):
            matched = child.expect(patterns)
            if debug:
                transcript.append(child.before or "")
                if isinstance(child.after, str):
                    transcript.append(child.after)
            if matched == 0:
                return outcome(success=True, authenticated=True, changed=changed)
            if matched == 1:
                authenticated = True
                onboarding_seen = True
                pending_password_change = True
                child.sendline(candidate["password"])
            elif matched in (2, 3):
                authenticated = True
                onboarding_seen = True
                prompt = child.after if isinstance(child.after, str) else ""
                if matched == 2:
                    active_password_kind = (
                        "user"
                        if pending_created_user_password
                        or re.search(r"(?i)\buser(?:\s+\([^)]+\))?\s+password", prompt)
                        else "account"
                    )
                elif active_password_kind is None:
                    active_password_kind = (
                        "user"
                        if re.search(r"(?i)\buser(?:\s+\([^)]+\))?\s+password", prompt)
                        else "account"
                    )
                new_password = (
                    onboarding.get("user_password", onboarding.get("password"))
                    if active_password_kind == "user"
                    else onboarding.get("password")
                )
                if not isinstance(new_password, str) or not new_password:
                    child.sendcontrol("c")
                    return outcome(success=True, authenticated=True, changed=False, cancelled=True)
                child.sendline(new_password)
                changed = True
                if matched == 2 and active_password_kind == "user":
                    created_user = True
                    pending_created_user_password = False
                elif matched == 2:
                    password_changed = True
                    pending_password_change = False
            elif matched == 4:
                authenticated = True
                onboarding_seen = True
                new_username = onboarding.get("username")
                if not isinstance(new_username, str) or not new_username:
                    child.sendcontrol("c")
                    return outcome(success=True, authenticated=True, changed=False, cancelled=True)
                child.sendline(new_username)
                changed = True
                pending_created_user_password = True
            elif matched == 5:
                child.sendline("")
            elif matched == 6:
                if login_password_sent or authenticated:
                    if pending_password_change or pending_created_user_password:
                        password_kind = "user" if pending_created_user_password else "account"
                        new_password = (
                            onboarding.get("user_password", onboarding.get("password"))
                            if password_kind == "user"
                            else onboarding.get("password")
                        )
                        if not isinstance(new_password, str) or not new_password:
                            child.sendcontrol("c")
                            return outcome(success=True, authenticated=True, changed=changed, cancelled=True)
                        child.sendline(new_password)
                        changed = True
                        if password_kind == "user":
                            created_user = True
                        else:
                            password_changed = True
                        pending_password_change = False
                        pending_created_user_password = False
                    else:
                        child.sendcontrol("c")
                        return outcome(success=authenticated, authenticated=authenticated, changed=changed)
                else:
                    child.sendline(candidate["password"])
                    login_password_sent = True
            elif matched == 7:
                return outcome(success=False, authenticated=False, reason="authentication rejected")
            elif matched == 8:
                return outcome(success=False, authenticated=False, fatal=True, reason="SSH host-key verification failed")
            elif matched == 9:
                child.close()
                if child.exitstatus == 0 and (authenticated or login_password_sent) and not onboarding_seen:
                    return outcome(success=True, authenticated=True, changed=changed)
                return outcome(success=authenticated, authenticated=authenticated, changed=changed, reason="SSH session closed")
            else:
                return outcome(success=authenticated, authenticated=authenticated, changed=changed, reason="SSH prompt timed out")
        return outcome(success=False, authenticated=authenticated, reason="too many interactive prompts")
    finally:
        if child.isalive():
            child.close(force=True)


class ActionModule(ActionBase):
    """Run credential discovery on the Ansible controller."""

    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(task_vars=task_vars)
        args = self._task.args

        if pexpect is None:
            raise AnsibleActionFail("slawo.ssh_bootstrap.discover_credentials requires pexpect on the controller")

        host = args.get("host") or task_vars.get("ansible_host") or task_vars.get("inventory_hostname")
        if not isinstance(host, str) or not host:
            raise AnsibleActionFail("host must be provided or resolvable from inventory")

        credentials = _validated_credentials(args.get("credentials"))
        port = args.get("port", task_vars.get("ansible_port", 22))
        timeout = args.get("timeout", 10)
        debug = args.get("debug", False)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise AnsibleActionFail("port must be an integer between 1 and 65535")
        if not isinstance(timeout, int) or timeout < 1:
            raise AnsibleActionFail("timeout must be a positive integer")
        if not isinstance(debug, bool):
            raise AnsibleActionFail("debug must be a boolean")

        host_key_checking = args.get("host_key_checking", "yes")
        if host_key_checking not in ("yes", "accept-new"):
            raise AnsibleActionFail("host_key_checking must be 'yes' or 'accept-new'")

        onboarding = args.get("onboarding", {})
        if not isinstance(onboarding, dict):
            raise AnsibleActionFail("onboarding must be a dictionary")
        custom_prompts = args.get("prompt_patterns", {})
        if not isinstance(custom_prompts, dict):
            raise AnsibleActionFail("prompt_patterns must be a dictionary")
        unknown_prompts = set(custom_prompts) - set(DEFAULT_PROMPTS)
        if unknown_prompts:
            raise AnsibleActionFail(f"unknown prompt_patterns keys: {', '.join(sorted(unknown_prompts))}")
        prompts = {**DEFAULT_PROMPTS, **custom_prompts}
        for name, pattern in prompts.items():
            try:
                re.compile(pattern)
            except (TypeError, re.error) as exc:
                raise AnsibleActionFail(f"invalid {name} prompt pattern: {exc}") from exc

        if self._task.check_mode:
            result.update(changed=False, skipped=True, msg="credential discovery is not performed in check mode")
            return result

        failures = []
        debug_sessions = []
        for candidate in credentials:
            command = _ssh_command(host, port, candidate["username"], host_key_checking)
            attempt = _attempt(command, candidate, onboarding, prompts, timeout, debug)
            if debug:
                debug_sessions.append(
                    {
                        "attempt": len(failures) + 1,
                        "username": candidate["username"],
                        "session": attempt.get("session", ""),
                        "reason": attempt.get("reason"),
                    }
                )
            if attempt.get("fatal"):
                result.update(failed=True, changed=False, msg=attempt["reason"])
                if debug:
                    result["sessions"] = debug_sessions
                return result
            if attempt.get("success"):
                if attempt.get("created_user"):
                    effective_username = onboarding["username"]
                    effective_password = onboarding.get("user_password", onboarding.get("password"))
                elif attempt.get("password_changed"):
                    effective_username = candidate["username"]
                    effective_password = onboarding["password"]
                else:
                    effective_username = candidate["username"]
                    effective_password = candidate["password"]
                result.update(
                    changed=attempt.get("changed", False),
                    credentials={"username": effective_username, "password": effective_password},
                    onboarding_cancelled=attempt.get("cancelled", False),
                    attempts=len(failures) + 1,
                )
                if debug:
                    result["sessions"] = debug_sessions
                return result
            failures.append(attempt.get("reason", "connection failed"))

        result.update(
            failed=True,
            changed=False,
            msg=f"none of the {len(credentials)} credential combinations succeeded",
            attempts=len(credentials),
        )
        if debug:
            result["sessions"] = debug_sessions
        return result

