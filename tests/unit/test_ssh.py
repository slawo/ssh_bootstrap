"""Unit tests for bounded SSH command execution."""

from pathlib import Path
import importlib.util
import unittest
from unittest.mock import patch


HELPER = Path(__file__).parents[2] / "plugins" / "plugin_utils" / "_ssh.py"
SPEC = importlib.util.spec_from_file_location("ssh_helper", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class FakeMatch:
    def __init__(self, value="0"):
        self.value = value

    def group(self, _index):
        return self.value


class FakeChild:
    def __init__(self, events):
        self.events = iter(events)
        self.before = ""
        self.match = FakeMatch()
        self.sent = []
        self.alive = True

    def expect(self, _patterns):
        index, self.before, group = next(self.events)
        self.match = FakeMatch(group)
        return index

    def sendline(self, value):
        self.sent.append(value)

    def isalive(self):
        return self.alive

    def close(self, force=False):
        self.alive = False


class SshCommandTests(unittest.TestCase):
    def test_passwords_are_not_in_process_arguments(self):
        argv = MODULE.ssh_argv("node.example", 22, "automation", "yes", "id -u")
        self.assertNotIn("login-secret", argv)
        self.assertNotIn("sudo-secret", argv)
        self.assertIn("automation@node.example", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)

    def test_login_and_sudo_password_prompts(self):
        child = FakeChild([(1, "", ""), (2, "ready", ""), (0, "0\n", "0")])
        with patch.object(MODULE.pexpect, "spawn", return_value=child):
            result = MODULE.run_command(
                host="node.example",
                port=22,
                username="automation",
                password="login-secret",
                sudo_password="sudo-secret",
                host_key_checking="yes",
                command=f"sudo -S -p '{MODULE.SUDO_PROMPT}' id -u",
                timeout=5,
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["rc"], 0)
        self.assertEqual(child.sent, ["login-secret", "sudo-secret"])

    def test_debug_output_redacts_both_passwords(self):
        child = FakeChild([(1, "login-secret ", ""), (2, "sudo-secret ", ""), (0, "done", "0")])
        with patch.object(MODULE.pexpect, "spawn", return_value=child):
            result = MODULE.run_command(
                host="node.example",
                port=22,
                username="automation",
                password="login-secret",
                sudo_password="sudo-secret",
                host_key_checking="yes",
                command="true",
                timeout=5,
                debug=True,
            )
        self.assertNotIn("login-secret", result["session"])
        self.assertNotIn("sudo-secret", result["session"])
        self.assertIn("********", result["session"])


if __name__ == "__main__":
    unittest.main()
