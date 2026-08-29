"""Pure orchestration for credential discovery and single-user provisioning."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def _connection(base: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    return {**base, "username": candidate["username"], "password": candidate["password"]}


def _credentials(candidate: dict[str, Any], access: dict[str, Any], include_password: bool) -> dict[str, Any]:
    result = {
        "username": candidate["username"],
        "uid": access["uid"],
        "is_root": access["is_root"],
    }
    if include_password:
        result["password"] = candidate["password"]
    return result


def _successful_result(
    candidate: dict[str, Any],
    access: dict[str, Any],
    workflow: dict[str, Any],
    *,
    changed: bool,
    attempts: int,
    force_password: bool = False,
) -> dict[str, Any]:
    include_password = force_password or workflow["return_password"] or candidate["source"] == "credentials"
    result = {
        "success": True,
        "changed": changed,
        "attempts": attempts,
        "credentials": _credentials(candidate, access, include_password),
        "become": {
            "enabled": not access["is_root"] and access["can_become"],
            "method": "sudo" if not access["is_root"] and access["can_become"] else None,
            "user": workflow["root"]["username"],
        },
    }
    return result


def execute_workflow(
    *,
    workflow: dict[str, Any],
    candidates: list[dict[str, Any]],
    connection_base: dict[str, Any],
    run_command: Callable[..., dict[str, Any]],
    run_script: Callable[..., dict[str, Any]],
    probe_access: Callable[..., dict[str, Any]],
    detect_platform: Callable[..., dict[str, Any]],
    sudo_install_command: Callable[..., str],
    build_provision_script: Callable[..., str],
) -> dict[str, Any]:
    privileged: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None
    failures = []
    attempts = 0

    for candidate in candidates:
        attempts += 1
        connection = _connection(connection_base, candidate)
        access = probe_access(run_command, connection)
        if not access.get("success"):
            failures.append(access.get("reason", "login or identity probe failed"))
            continue
        if candidate["source"] == "onboarding" and access.get("can_become"):
            return _successful_result(candidate, access, workflow, changed=False, attempts=attempts)
        if access.get("can_become"):
            privileged = candidate, connection, access
            break
        failures.append(f"{candidate['username']} authenticated without UID 0 or working sudo")

    if privileged is None:
        return {
            "success": False,
            "changed": False,
            "attempts": attempts,
            "reason": "no credential provided usable privileged access",
            "failures": failures,
        }

    privileged_candidate, privileged_connection, privileged_access = privileged
    onboarding = workflow["onboarding"]
    if onboarding["username"] is None:
        return _successful_result(
            privileged_candidate, privileged_access, workflow, changed=False, attempts=attempts
        )

    platform = detect_platform(run_command, privileged_connection)
    if not platform.get("success"):
        return {"success": False, "changed": False, "attempts": attempts, "reason": platform["reason"]}

    if not privileged_access["sudo_available"]:
        if not workflow["install_sudo"]:
            return _successful_result(
                privileged_candidate,
                privileged_access,
                workflow,
                changed=False,
                attempts=attempts,
                force_password=True,
            )
        install = sudo_install_command(platform)
        install_result = run_script(
            **privileged_connection,
            script=install,
            become=not privileged_access["is_root"],
            sudo_password=None if privileged_access["is_root"] else privileged_connection["password"],
        )
        if not install_result.get("success") or install_result.get("rc") != 0:
            return {
                "success": False,
                "changed": False,
                "attempts": attempts,
                "reason": install_result.get("reason", "sudo installation failed"),
            }

    script = build_provision_script(
        family=platform["family"], onboarding=onboarding, root=workflow["root"]
    )
    provision = run_script(
        **privileged_connection,
        script=script,
        become=not privileged_access["is_root"],
        sudo_password=None if privileged_access["is_root"] else privileged_connection["password"],
        secrets=tuple(
            secret for secret in (onboarding["password"], workflow["root"]["password"]) if secret
        ),
    )
    if not provision.get("success") or provision.get("rc") != 0:
        return {
            "success": False,
            "changed": False,
            "attempts": attempts,
            "reason": provision.get("reason", "user provisioning failed"),
        }

    user_candidate = {
        "username": onboarding["username"],
        "password": onboarding["password"],
        "source": "onboarding",
    }
    user_access = probe_access(run_command, _connection(connection_base, user_candidate))
    if not user_access.get("success") or not user_access.get("can_become"):
        return {
            "success": False,
            "changed": True,
            "attempts": attempts + 1,
            "reason": "provisioned user failed SSH or sudo verification",
        }
    return _successful_result(
        user_candidate, user_access, workflow, changed=True, attempts=attempts + 1
    )
