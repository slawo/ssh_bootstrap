"""Bounded password-authenticated SSH command and script execution."""

from __future__ import annotations

import re
import shlex
from typing import Any

try:
    import pexpect
except ImportError:  # pragma: no cover
    pexpect = None

RESULT_PREFIX = "__ANSIBLE_SSH_BOOTSTRAP_RC_"
READY_MARKER = "__ANSIBLE_SSH_BOOTSTRAP_STDIN_READY__"
SUDO_PROMPT = "__ANSIBLE_SSH_BOOTSTRAP_SUDO_PASSWORD__"
RESULT_PATTERN = re.escape(RESULT_PREFIX) + r"([0-9]+)__"
LOGIN_PASSWORD_PATTERN = r"(?i)(?:password|passphrase)\s*:\s*$"
DENIED_PATTERN = r"(?i)permission denied|authentication failed"
HOST_KEY_PATTERN = r"(?i)host key verification failed|remote host identification has changed"


def _base_ssh_argv(host: str, port: int, username: str, host_key_checking: str) -> list[str]:
    return [
        "ssh", "-tt", "-p", str(port), "-o", "BatchMode=no", "-o",
        "PreferredAuthentications=keyboard-interactive,password", "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1", "-o", f"StrictHostKeyChecking={host_key_checking}",
        "-o", "LogLevel=ERROR", "--", f"{username}@{host}",
    ]


def ssh_argv(host: str, port: int, username: str, host_key_checking: str, command: str) -> list[str]:
    wrapped = f"{command}\ncommand_rc=$?\nprintf '\n{RESULT_PREFIX}%s__\n' \"$command_rc\""
    return [*_base_ssh_argv(host, port, username, host_key_checking), "sh", "-c", shlex.quote(wrapped)]


def script_argv(host: str, port: int, username: str, host_key_checking: str, become: bool) -> list[str]:
    shell = f"printf '{READY_MARKER}\\n'; exec sh -s"
    remote = ["sh", "-c", shlex.quote(shell)]
    if become:
        remote = ["sudo", "-S", "-p", shlex.quote(SUDO_PROMPT), "--", *remote]
    return [*_base_ssh_argv(host, port, username, host_key_checking), *remote]


def _redacted(text: str, secrets: tuple[str | None, ...]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "********")
    return text


def run_command(*, host: str, port: int, username: str, password: str, host_key_checking: str,
                command: str, timeout: int, sudo_password: str | None = None,
                debug: bool = False) -> dict[str, Any]:
    if pexpect is None:
        raise RuntimeError("pexpect is required")
    argv = ssh_argv(host, port, username, host_key_checking, command)
    child = pexpect.spawn(argv[0], argv[1:], encoding="utf-8", timeout=timeout, echo=False)
    patterns = [RESULT_PATTERN, LOGIN_PASSWORD_PATTERN, re.escape(SUDO_PROMPT), DENIED_PATTERN,
                HOST_KEY_PATTERN, pexpect.EOF, pexpect.TIMEOUT]
    transcript: list[str] = []
    login_password_sent = False

    def outcome(**values: Any) -> dict[str, Any]:
        output = _redacted("".join(transcript), (password, sudo_password))
        values["stdout"] = output
        if debug:
            values["session"] = output
        return values

    try:
        for _unused in range(12):
            matched = child.expect(patterns)
            transcript.append(child.before or "")
            if matched == 0:
                return outcome(success=True, rc=int(child.match.group(1)))
            if matched == 1:
                if login_password_sent:
                    return outcome(success=False, reason="unexpected repeated SSH password prompt")
                child.sendline(password)
                login_password_sent = True
            elif matched == 2:
                if sudo_password is None:
                    return outcome(success=False, reason="sudo requested a password but none was available")
                child.sendline(sudo_password)
            elif matched == 3:
                return outcome(success=False, reason="authentication rejected")
            elif matched == 4:
                return outcome(success=False, fatal=True, reason="SSH host-key verification failed")
            elif matched == 5:
                return outcome(success=False, reason="SSH session closed before returning command status")
            else:
                return outcome(success=False, reason="SSH command timed out")
        return outcome(success=False, reason="too many interactive prompts")
    finally:
        if child.isalive():
            child.close(force=True)


def run_script(*, host: str, port: int, username: str, password: str, host_key_checking: str,
               script: str, timeout: int, become: bool = False, sudo_password: str | None = None,
               secrets: tuple[str, ...] = (), debug: bool = False) -> dict[str, Any]:
    if pexpect is None:
        raise RuntimeError("pexpect is required")
    argv = script_argv(host, port, username, host_key_checking, become)
    child = pexpect.spawn(argv[0], argv[1:], encoding="utf-8", timeout=timeout, echo=False)
    patterns = [re.escape(READY_MARKER), RESULT_PATTERN, LOGIN_PASSWORD_PATTERN, re.escape(SUDO_PROMPT),
                DENIED_PATTERN, HOST_KEY_PATTERN, pexpect.EOF, pexpect.TIMEOUT]
    transcript: list[str] = []
    login_password_sent = False
    payload_sent = False

    def outcome(**values: Any) -> dict[str, Any]:
        output = _redacted("".join(transcript), (password, sudo_password, *secrets))
        values["stdout"] = output
        if debug:
            values["session"] = output
        return values

    try:
        for _unused in range(14):
            matched = child.expect(patterns)
            transcript.append(child.before or "")
            if matched == 0:
                if payload_sent:
                    return outcome(success=False, reason="remote shell emitted a repeated readiness marker")
                payload = "(\n" + script + ("" if script.endswith("\n") else "\n") + ")\n"
                payload += f"script_rc=$?\nprintf '\n{RESULT_PREFIX}%s__\n' \"$script_rc\"\n"
                child.send(payload)
                child.sendcontrol("d")
                payload_sent = True
            elif matched == 1:
                if not payload_sent:
                    return outcome(success=False, reason="remote shell returned status before accepting the script")
                return outcome(success=True, rc=int(child.match.group(1)))
            elif matched == 2:
                if login_password_sent:
                    return outcome(success=False, reason="unexpected repeated SSH password prompt")
                child.sendline(password)
                login_password_sent = True
            elif matched == 3:
                if sudo_password is None:
                    return outcome(success=False, reason="sudo requested a password but none was available")
                child.sendline(sudo_password)
            elif matched == 4:
                return outcome(success=False, reason="authentication rejected")
            elif matched == 5:
                return outcome(success=False, fatal=True, reason="SSH host-key verification failed")
            elif matched == 6:
                return outcome(success=False, reason="SSH session closed before returning script status")
            else:
                return outcome(success=False, reason="SSH script timed out")
        return outcome(success=False, reason="too many interactive prompts")
    finally:
        if child.isalive():
            child.close(force=True)
