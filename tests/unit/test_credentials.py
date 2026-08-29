"""Unit tests for opt-in credential profiles."""

from pathlib import Path
import importlib.util
import unittest


HELPER = Path(__file__).parents[2] / "plugins" / "plugin_utils" / "_credentials.py"
SPEC = importlib.util.spec_from_file_location("credentials_helper", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class CredentialProfileTests(unittest.TestCase):
    def test_current_documented_profiles_are_opt_in(self):
        self.assertEqual(MODULE.credentials_for_profiles([]), [])
        self.assertEqual(
            MODULE.credentials_for_profiles(["armbian", "ubuntu_raspberry_pi"]),
            [
                {"username": "root", "password": "1234", "source": "profile", "profile": "armbian"},
                {"username": "ubuntu", "password": "ubuntu", "source": "profile", "profile": "ubuntu_raspberry_pi"},
            ],
        )

    def test_removed_raspberry_pi_default_is_explicitly_legacy(self):
        self.assertNotIn("raspberry_pi_os", MODULE.PROFILES)
        self.assertEqual(
            MODULE.credentials_for_profiles(["raspberry_pi_os_legacy"])[0]["username"], "pi"
        )

    def test_unknown_profile_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown credential profile"):
            MODULE.credentials_for_profiles(["folklore"])


if __name__ == "__main__":
    unittest.main()
