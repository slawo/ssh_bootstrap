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
        self.controls = []
        self.alive = True

    def expect(self, _patterns):
        index, self.before, group = next(self.events)
        self.match = FakeMatch(group)
        return index

    def sendline(self, value):
        self.sent.append(value)

    def send(self, value):
        self.sent.append(value)

    def sendcontrol(self, value):
        self.controls.append(value)

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


    def test_script_and_secrets_are_not_in_process_arguments(self):
        argv = MODULE.script_argv("node.example", 22, "automation", "yes", True)
        joined = " ".join(argv)
        self.assertNotIn("user-secret", joined)
        self.assertNotIn("useradd automation", joined)
        self.assertIn("sudo", argv)

    def test_script_is_streamed_after_login_and_sudo(self):
        child = FakeChild([(2, "", ""), (3, "", ""), (0, "", ""), (1, "provisioned", "0")])
        with patch.object(MODULE.pexpect, "spawn", return_value=child):
            result = MODULE.run_script(host="node.example", port=22, username="automation", password="login-secret", sudo_password="sudo-secret", host_key_checking="yes", script="useradd automation", timeout=5, become=True)
        self.assertTrue(result["success"])
        self.assertEqual(child.sent[:2], ["login-secret", "sudo-secret"])
        self.assertIn("useradd automation", child.sent[2])
        self.assertEqual(child.controls, ["d"])

    def test_streamed_secrets_are_redacted(self):
        child = FakeChild([(2, "", ""), (0, "", ""), (1, "user-secret root-secret", "0")])
        with patch.object(MODULE.pexpect, "spawn", return_value=child):
            result = MODULE.run_script(host="node.example", port=22, username="root", password="login-secret", host_key_checking="yes", script="printf user-secret", timeout=5, secrets=("user-secret", "root-secret"), debug=True)
        self.assertNotIn("user-secret", result["session"])
        self.assertNotIn("root-secret", result["session"])


if __name__ == "__main__":
    unittest.main()
