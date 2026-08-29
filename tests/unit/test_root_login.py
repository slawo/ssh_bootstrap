"""Unit tests for guarded privileged SSH-login disabling."""

from pathlib import Path
import importlib.util
import subprocess
import unittest


HELPER = Path(__file__).parents[2] / "plugins" / "plugin_utils" / "_root_login.py"
SPEC = importlib.util.spec_from_file_location("root_login_helper", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class RootLoginTests(unittest.TestCase):
    def test_policy_check_uses_sudo_and_exact_managed_rule(self):
        command = MODULE.build_root_login_disabled_command("toor")
        self.assertIn("sudo -S", command)
        self.assertIn(MODULE.SUDO_PROMPT, command)
        self.assertIn("00-ansible-ssh-bootstrap.conf", command)
        self.assertIn("DenyUsers toor", command)

    def test_disable_script_has_validation_reload_and_timed_rollback(self):
        script = MODULE.build_disable_root_login_script("toor", "a" * 32)
        self.assertIn("DenyUsers %s", script)
        self.assertIn(" toor >", script)
        self.assertIn("sshd -t", script)
        self.assertIn("sleep 60", script)
        self.assertIn('if ! test -f "$state/commit"', script)
        self.assertIn('"$state/reload_sshd" "$state/reload_kind"', script)

    def test_reload_mechanism_is_selected_once_and_reused_by_rollback(self):
        script = MODULE.build_disable_root_login_script("root", "c" * 32)
        self.assertIn("systemctl is-active --quiet sshd.service", script)
        self.assertIn("systemctl is-active --quiet ssh.service", script)
        self.assertIn("rcctl check sshd", script)
        self.assertIn("service sshd status", script)
        self.assertIn("service ssh status", script)
        self.assertIn('case "$(cat "$1")"', script)
        self.assertNotIn("systemctl reload sshd 2>/dev/null ||", script)

    def test_unknown_reload_mechanism_fails_before_configuration_change(self):
        script = MODULE.build_disable_root_login_script("root", "d" * 32)
        detection = script.index("unable to identify the active SSH service")
        backup = script.index('cp -p "$config"')
        deny = script.index("DenyUsers")
        self.assertLess(detection, backup)
        self.assertLess(detection, deny)

    def test_watchdog_is_armed_before_configuration_mutation(self):
        script = MODULE.build_disable_root_login_script("root", "e" * 32)
        watchdog = script.index("nohup sh -c 'sleep 60")
        include_write = script.index("cat \"$temporary\" > \"$config\"")
        deny_write = script.index("DenyUsers")
        self.assertLess(watchdog, include_write)
        self.assertLess(watchdog, deny_write)

    def test_generated_scripts_have_valid_posix_shell_syntax(self):
        for script in (
            MODULE.build_disable_root_login_script("root", "f" * 32),
            MODULE.build_commit_root_login_script("0" * 32),
        ):
            checked = subprocess.run(
                ["sh", "-n"], input=script, text=True, capture_output=True, check=False
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)

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
