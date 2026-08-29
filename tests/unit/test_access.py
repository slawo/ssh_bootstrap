"""Unit tests for remote privilege probing."""

from pathlib import Path
import importlib.util
import unittest


HELPER = Path(__file__).parents[2] / "plugins" / "plugin_utils" / "_access.py"
SPEC = importlib.util.spec_from_file_location("access_helper", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class RecordingRunner:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return next(self.results)


class AccessProbeTests(unittest.TestCase):
    def setUp(self):
        self.connection = {
            "host": "node.example",
            "port": 22,
            "username": "automation",
            "password": "user-secret",
            "host_key_checking": "yes",
            "timeout": 5,
        }

    def test_uid_zero_is_privileged_regardless_of_name(self):
        runner = RecordingRunner(
            [{"success": True, "rc": 0, "stdout": "__SSH_BOOTSTRAP_UID__0\n__SSH_BOOTSTRAP_USER__toor\n__SSH_BOOTSTRAP_METHOD__none\n"}]
        )
        result = MODULE.probe_access(runner, self.connection)
        self.assertTrue(result["is_root"])
        self.assertTrue(result["can_become"])
        self.assertEqual(result["username"], "toor")
        self.assertEqual(len(runner.calls), 1)

    def test_sudo_must_really_reach_uid_zero(self):
        runner = RecordingRunner(
            [
                {"success": True, "rc": 0, "stdout": "__SSH_BOOTSTRAP_UID__1000\n__SSH_BOOTSTRAP_USER__automation\n__SSH_BOOTSTRAP_METHOD__sudo\n"},
                {"success": True, "rc": 0, "stdout": "__SSH_BOOTSTRAP_BECOME_UID__0\n"},
            ]
        )
        result = MODULE.probe_access(runner, self.connection)
        self.assertFalse(result["is_root"])
        self.assertTrue(result["can_become"])
        self.assertEqual(result["become_method"], "sudo")
        self.assertEqual(runner.calls[1]["sudo_password"], "user-secret")

    def test_group_membership_without_working_sudo_is_not_enough(self):
        runner = RecordingRunner(
            [
                {"success": True, "rc": 0, "stdout": "__SSH_BOOTSTRAP_UID__1000\n__SSH_BOOTSTRAP_USER__automation\n__SSH_BOOTSTRAP_METHOD__sudo\n"},
                {"success": True, "rc": 1, "stdout": ""},
            ]
        )
        result = MODULE.probe_access(runner, self.connection)
        self.assertFalse(result["can_become"])

    def test_doas_must_really_reach_uid_zero(self):
        runner = RecordingRunner(
            [
                {"success": True, "rc": 0, "stdout": "__SSH_BOOTSTRAP_UID__1000\n__SSH_BOOTSTRAP_USER__automation\n__SSH_BOOTSTRAP_METHOD__doas\n"},
                {"success": True, "rc": 0, "stdout": "__SSH_BOOTSTRAP_BECOME_UID__0\n"},
            ]
        )
        result = MODULE.probe_access(runner, self.connection)
        self.assertTrue(result["can_become"])
        self.assertEqual(result["become_method"], "doas")
        self.assertTrue(runner.calls[1]["command"].startswith("doas "))

    def test_missing_escalation_tool_is_reported(self):
        runner = RecordingRunner(
            [{"success": True, "rc": 0, "stdout": "__SSH_BOOTSTRAP_UID__1000\n__SSH_BOOTSTRAP_USER__automation\n__SSH_BOOTSTRAP_METHOD__none\n"}]
        )
        result = MODULE.probe_access(runner, self.connection)
        self.assertFalse(result["sudo_available"])
        self.assertFalse(result["escalation_available"])
        self.assertFalse(result["can_become"])


if __name__ == "__main__":
    unittest.main()
