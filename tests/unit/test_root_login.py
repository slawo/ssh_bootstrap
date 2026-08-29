"""Unit tests for guarded privileged SSH-login disabling."""

from pathlib import Path
import importlib.util
import unittest


HELPER = Path(__file__).parents[2] / "plugins" / "plugin_utils" / "_root_login.py"
SPEC = importlib.util.spec_from_file_location("root_login_helper", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class RootLoginTests(unittest.TestCase):
    def test_disable_script_has_validation_reload_and_timed_rollback(self):
        script = MODULE.build_disable_root_login_script("toor", "a" * 32)
        self.assertIn("DenyUsers %s", script)
        self.assertIn(" toor >", script)
        self.assertIn("sshd -t", script)
        self.assertIn("sleep 60", script)
        self.assertIn('if ! test -f "$1/commit"', script)
        self.assertIn("rcctl reload sshd", script)

    def test_commit_script_marks_guard_before_deferred_cleanup(self):
        script = MODULE.build_commit_root_login_script("b" * 32)
        self.assertIn(': > "$state/commit"', script)
        self.assertIn("sleep 75", script)

    def test_unsafe_account_and_token_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "username"):
            MODULE.build_disable_root_login_script("root; reboot", "a" * 32)
        with self.assertRaisesRegex(ValueError, "token"):
            MODULE.build_commit_root_login_script("../unsafe")


if __name__ == "__main__":
    unittest.main()
