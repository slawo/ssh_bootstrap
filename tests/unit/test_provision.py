"""Unit tests for privileged account provisioning scripts."""

from pathlib import Path
import importlib.util
import unittest


HELPER = Path(__file__).parents[2] / "plugins" / "plugin_utils" / "_provision.py"
SPEC = importlib.util.spec_from_file_location("provision_helper", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ProvisionTests(unittest.TestCase):
    def config(self, passwordless=True, root_password="root-secret"):
        return {
            "onboarding": {
                "username": "automation",
                "password": "user-secret",
                "passwordless_sudo": passwordless,
            },
            "root": {"username": "toor", "password": root_password},
        }

    def test_linux_creates_or_updates_user_and_both_passwords(self):
        config = self.config()
        script = MODULE.build_provision_script(family="debian", **config)
        self.assertIn("if ! id automation", script)
        self.assertIn("useradd --create-home", script)
        self.assertIn("automation user-secret", script)
        self.assertIn("toor root-secret", script)

    def test_openbsd_uses_native_account_tools(self):
        config = self.config()
        script = MODULE.build_provision_script(family="openbsd", **config)
        self.assertIn("useradd -m -s /bin/ksh", script)
        self.assertIn("chpass -p", script)
        self.assertIn("encrypt user-secret", script)
        self.assertIn("permit nopass automation as root", script)
        self.assertIn("doas -C", script)
        self.assertNotIn("sudoers", script)
        self.assertNotIn("visudo", script)

    def test_openbsd_password_required_doas_policy(self):
        config = self.config(passwordless=False)
        script = MODULE.build_provision_script(family="openbsd", **config)
        self.assertIn("permit automation as root", script)
        self.assertNotIn("permit nopass", script)

    def test_passwordless_sudo_is_default_policy(self):
        config = self.config(passwordless=True)
        script = MODULE.build_provision_script(family="fedora", **config)
        self.assertIn("automation ALL=(ALL:ALL) NOPASSWD: ALL", script)
        self.assertIn("visudo -cf", script)
        self.assertIn("chmod 0440", script)

    def test_password_required_sudo_override(self):
        config = self.config(passwordless=False)
        script = MODULE.build_provision_script(family="arch", **config)
        self.assertIn("automation ALL=(ALL:ALL) ALL", script)
        self.assertNotIn("NOPASSWD", script)

    def test_root_password_update_can_be_omitted(self):
        config = self.config(root_password=None)
        script = MODULE.build_provision_script(family="debian", **config)
        self.assertNotIn("toor", script)

    def test_unsafe_username_is_rejected(self):
        config = self.config()
        config["onboarding"]["username"] = "bad;name"
        with self.assertRaisesRegex(ValueError, "unsupported"):
            MODULE.build_provision_script(family="debian", **config)


if __name__ == "__main__":
    unittest.main()
