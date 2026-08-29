"""Unit tests for platform detection and sudo installation strategy."""

from pathlib import Path
import importlib.util
import unittest


HELPER = Path(__file__).parents[2] / "plugins" / "plugin_utils" / "_platform.py"
SPEC = importlib.util.spec_from_file_location("platform_helper", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def platform_output(system, platform_id="", id_like=""):
    return (
        f"__SSH_BOOTSTRAP_SYSTEM__{system}\n"
        f"__SSH_BOOTSTRAP_ID__{platform_id}\n"
        f"__SSH_BOOTSTRAP_ID_LIKE__{id_like}\n"
    )


class PlatformTests(unittest.TestCase):
    def test_debian_family_platforms_use_apt(self):
        for platform_id, id_like in (("debian", ""), ("ubuntu", "debian"), ("armbian", "debian ubuntu")):
            with self.subTest(platform_id=platform_id):
                result = MODULE.parse_platform(platform_output("Linux", platform_id, id_like))
                self.assertEqual(result["family"], "debian")
                self.assertEqual(result["package_manager"], "apt")

    def test_fedora_uses_dnf(self):
        result = MODULE.parse_platform(platform_output("Linux", "fedora"))
        self.assertEqual(result["package_manager"], "dnf")

    def test_arch_uses_pacman(self):
        result = MODULE.parse_platform(platform_output("Linux", "arch"))
        self.assertEqual(result["package_manager"], "pacman")

    def test_openbsd_uses_pkg_add_without_os_release(self):
        result = MODULE.parse_platform(platform_output("OpenBSD"))
        self.assertEqual(result["family"], "openbsd")
        self.assertEqual(result["package_manager"], "pkg_add")

    def test_unknown_platform_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported platform"):
            MODULE.parse_platform(platform_output("Linux", "mystery"))

    def test_install_commands_are_noninteractive(self):
        apt = MODULE.sudo_install_command({"package_manager": "apt"})
        dnf = MODULE.sudo_install_command({"package_manager": "dnf"})
        pacman = MODULE.sudo_install_command({"package_manager": "pacman"})
        self.assertIn("DEBIAN_FRONTEND=noninteractive", apt)
        self.assertIn("-y", dnf)
        self.assertIn("--noconfirm", pacman)

    def test_openbsd_never_installs_sudo(self):
        with self.assertRaisesRegex(ValueError, "base-system doas"):
            MODULE.sudo_install_command({"family": "openbsd", "package_manager": "pkg_add"})


if __name__ == "__main__":
    unittest.main()
