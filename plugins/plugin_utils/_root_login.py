"""Build guarded scripts for disabling SSH access to a privileged account."""

from __future__ import annotations

import re
import shlex


_SAFE_ACCOUNT = re.compile(r"^[a-z_][a-z0-9_.-]*[$]?$", re.ASCII)
_SAFE_TOKEN = re.compile(r"^[a-f0-9]{32}$", re.ASCII)


def _validated(root_username: str, guard_token: str) -> tuple[str, str]:
    if not _SAFE_ACCOUNT.fullmatch(root_username):
        raise ValueError("root username contains unsupported characters")
    if not _SAFE_TOKEN.fullmatch(guard_token):
        raise ValueError("root-login guard token must be 32 lowercase hexadecimal characters")
    return shlex.quote(root_username), guard_token


def build_disable_root_login_script(root_username: str, guard_token: str) -> str:
    """Install a deny rule, start rollback guard, validate, and reload sshd."""
    account, token = _validated(root_username, guard_token)
    state = f"/var/tmp/ansible-ssh-bootstrap-{token}"
    return f"""set -eu
state={state}
config=/etc/ssh/sshd_config
dropin=/etc/ssh/sshd_config.d/00-ansible-ssh-bootstrap.conf
test -f "$config"
mkdir -p /etc/ssh/sshd_config.d "$state"
cp -p "$config" "$state/sshd_config"
if test -f "$dropin"; then cp -p "$dropin" "$state/dropin"; else : > "$state/no_dropin"; fi
if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\\.d/\\*\\.conf([[:space:]]|$)' "$config"; then
    temporary="$state/sshd_config.new"
    printf '%s\\n' 'Include /etc/ssh/sshd_config.d/*.conf' > "$temporary"
    cat "$config" >> "$temporary"
    cat "$temporary" > "$config"
fi
printf 'DenyUsers %s\\n' {account} > "$dropin"
rollback='if ! test -f "$1/commit"; then cp -p "$1/sshd_config" /etc/ssh/sshd_config; if test -f "$1/no_dropin"; then rm -f /etc/ssh/sshd_config.d/00-ansible-ssh-bootstrap.conf; else cp -p "$1/dropin" /etc/ssh/sshd_config.d/00-ansible-ssh-bootstrap.conf; fi; sshd -t && (systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || rcctl reload sshd); fi'
nohup sh -c 'sleep 60; sh -c "$1" guard "$2"' guard "$rollback" "$state" >/dev/null 2>&1 &
sshd -t
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload 2>/dev/null || service ssh reload 2>/dev/null || rcctl reload sshd
"""


def build_commit_root_login_script(guard_token: str) -> str:
    """Commit a guarded SSH configuration change after reconnect verification."""
    _account, token = _validated("root", guard_token)
    state = f"/var/tmp/ansible-ssh-bootstrap-{token}"
    return f"""set -eu
state={state}
test -d "$state"
: > "$state/commit"
nohup sh -c 'sleep 75; rm -rf "$1"' cleanup "$state" >/dev/null 2>&1 &
"""
