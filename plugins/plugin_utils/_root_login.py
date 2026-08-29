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
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet sshd.service; then
    printf '%s\\n' systemd-sshd > "$state/reload_kind"
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh.service; then
    printf '%s\\n' systemd-ssh > "$state/reload_kind"
elif command -v rcctl >/dev/null 2>&1 && rcctl check sshd >/dev/null 2>&1; then
    printf '%s\\n' rcctl-sshd > "$state/reload_kind"
elif command -v service >/dev/null 2>&1 && service sshd status >/dev/null 2>&1; then
    printf '%s\\n' service-sshd > "$state/reload_kind"
elif command -v service >/dev/null 2>&1 && service ssh status >/dev/null 2>&1; then
    printf '%s\\n' service-ssh > "$state/reload_kind"
else
    printf '%s\\n' 'unable to identify the active SSH service' >&2
    exit 1
fi
cat > "$state/reload_sshd" <<'RELOAD_SSHD'
#!/bin/sh
set -eu
case "$(cat "$1")" in
    systemd-sshd) exec systemctl reload sshd.service ;;
    systemd-ssh) exec systemctl reload ssh.service ;;
    rcctl-sshd) exec rcctl reload sshd ;;
    service-sshd) exec service sshd reload ;;
    service-ssh) exec service ssh reload ;;
    *) printf '%s\\n' 'invalid saved SSH reload mechanism' >&2; exit 1 ;;
esac
RELOAD_SSHD
chmod 0700 "$state/reload_sshd"
cp -p "$config" "$state/sshd_config"
if test -f "$dropin"; then cp -p "$dropin" "$state/dropin"; else : > "$state/no_dropin"; fi
cat > "$state/rollback" <<'ROLLBACK'
#!/bin/sh
set -eu
state=$1
if ! test -f "$state/commit"; then
    cp -p "$state/sshd_config" /etc/ssh/sshd_config
    if test -f "$state/no_dropin"; then
        rm -f /etc/ssh/sshd_config.d/00-ansible-ssh-bootstrap.conf
    else
        cp -p "$state/dropin" /etc/ssh/sshd_config.d/00-ansible-ssh-bootstrap.conf
    fi
    sshd -t
    "$state/reload_sshd" "$state/reload_kind"
fi
ROLLBACK
chmod 0700 "$state/rollback"
nohup sh -c 'sleep 60; exec "$1/rollback" "$1"' guard "$state" >/dev/null 2>&1 &
if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\\.d/\\*\\.conf([[:space:]]|$)' "$config"; then
    temporary="$state/sshd_config.new"
    printf '%s\\n' 'Include /etc/ssh/sshd_config.d/*.conf' > "$temporary"
    cat "$config" >> "$temporary"
    cat "$temporary" > "$config"
fi
printf 'DenyUsers %s\\n' {account} > "$dropin"
sshd -t
"$state/reload_sshd" "$state/reload_kind"
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
