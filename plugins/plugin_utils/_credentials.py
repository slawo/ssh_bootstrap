"""Opt-in credential profiles backed by vendor documentation."""

from __future__ import annotations

from typing import Any


PROFILES = {
    "armbian": ({"username": "root", "password": "1234"},),
    "ubuntu_raspberry_pi": ({"username": "ubuntu", "password": "ubuntu"},),
    "raspberry_pi_os_legacy": ({"username": "pi", "password": "raspberry"},),
}


def credentials_for_profiles(names: list[str]) -> list[dict[str, Any]]:
    """Expand explicitly selected profiles in caller-provided order."""
    result = []
    for name in names:
        if name not in PROFILES:
            raise ValueError(f"unknown credential profile: {name}")
        result.extend({**candidate, "source": "profile", "profile": name} for candidate in PROFILES[name])
    return result
