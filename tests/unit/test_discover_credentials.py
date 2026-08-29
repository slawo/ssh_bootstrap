"""Unit tests for the SSH credential discovery state machine."""

from pathlib import Path
import importlib.util
import unittest
from unittest.mock import patch


PLUGIN = Path(__file__).parents[2] / "plugins" / "action" / "discover_credentials.py"
SPEC = importlib.util.spec_from_file_location("discover_credentials", PLUGIN)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class FakeChild:
    def __init__(self, matches):
        self.matches = iter(matches)
        self.exitstatus = 0
        self.sent = []
        self.controls = []
        self.alive = True
        self.before = ""
        self.after = ""

    def expect(self, _patterns):
        match = next(self.matches)
        if isinstance(match, tuple):
            index, self.before, self.after = match
            return index
        self.before = ""
        self.after = ""
        return match

    def sendline(self, value):
        self.sent.append(value)

    def sendcontrol(self, value):
        self.controls.append(value)

    def isalive(self):
        return self.alive

    def close(self, force=False):
        self.alive = False


class DiscoverCredentialsTests(unittest.TestCase):
    def test_workflow_defaults(self):
        workflow = MODULE._validated_workflow({})
        self.assertEqual(workflow["root"]["username"], "root")
        self.assertTrue(workflow["root"]["login"])
        self.assertTrue(workflow["install_sudo"])
        self.assertTrue(workflow["onboarding"]["passwordless_sudo"])
        self.assertFalse(workflow["return_password"])

    def test_onboarding_requires_username_and_password(self):
        with self.assertRaisesRegex(Exception, "must be provided together"):
            MODULE._validated_workflow({"onboarding": {"username": "automation"}})

    def test_disabling_root_requires_onboarding_user(self):
        with self.assertRaisesRegex(Exception, "requires an onboarding user"):
            MODULE._validated_workflow({"root": {"disable_after_onboarding": True}})

    def test_candidate_order_and_deduplication(self):
        workflow = MODULE._validated_workflow(
            {
                "onboarding": {"username": "automation", "password": "user-secret"},
                "root": {"password": "root-secret"},
            }
        )
        candidates = MODULE._ordered_candidates(
            workflow,
            [
                {"username": "root", "password": "root-secret"},
                {"username": "factory", "password": "factory-secret"},
            ],
        )
        self.assertEqual([candidate["source"] for candidate in candidates], ["onboarding", "root", "credentials"])
        self.assertEqual(candidates[-1]["username"], "factory")

    def test_root_login_false_removes_root_from_fallbacks(self):
        workflow = MODULE._validated_workflow({"root": {"username": "toor", "login": False}})
        candidates = MODULE._ordered_candidates(
            workflow,
            [
                {"username": "toor", "password": "factory-secret"},
                {"username": "operator", "password": "operator-secret"},
            ],
        )
        self.assertEqual(
            candidates,
            [{"username": "operator", "password": "operator-secret", "source": "credentials"}],
        )

    def run_attempt(self, matches, onboarding=None, debug=False):
        child = FakeChild(matches)
        with patch.object(MODULE.pexpect, "spawn", return_value=child):
            result = MODULE._attempt(
                ["ssh"],
                {"username": "factory", "password": "factory-secret"},
                onboarding or {},
                MODULE.DEFAULT_PROMPTS,
                5,
                debug,
            )
        return result, child

    def test_login_then_success(self):
        result, child = self.run_attempt([6, 0])
        self.assertEqual(result, {"success": True, "authenticated": True, "changed": False})
        self.assertEqual(child.sent, ["factory-secret"])

    def test_forced_password_change(self):
        result, child = self.run_attempt([6, 1, 2, 3, 0], {"password": "new-secret"})
        self.assertTrue(result["success"])
        self.assertTrue(result["changed"])
        self.assertTrue(result["password_changed"])
        self.assertEqual(child.sent, ["factory-secret", "factory-secret", "new-secret", "new-secret"])

    def test_missing_new_password_cancels(self):
        result, child = self.run_attempt([6, 2])
        self.assertTrue(result["success"])
        self.assertTrue(result["cancelled"])
        self.assertEqual(child.controls, ["c"])

    def test_create_user_and_password(self):
        result, child = self.run_attempt(
            [
                6,
                4,
                (2, "", "Create user (Automation) password:"),
                (3, "", "Repeat user (Automation) password:"),
                5,
                0,
            ],
            {"username": "automation", "password": "account-secret", "user_password": "user-secret"},
        )
        self.assertTrue(result["changed"])
        self.assertTrue(result["created_user"])
        self.assertEqual(child.sent, ["factory-secret", "automation", "user-secret", "user-secret", ""])

    def test_created_user_password_falls_back_to_account_password(self):
        result, child = self.run_attempt(
            [
                6,
                4,
                (2, "", "Create user (Automation) password:"),
                (3, "", "Repeat user (Automation) password:"),
                0,
            ],
            {"username": "automation", "password": "shared-secret"},
        )
        self.assertTrue(result["created_user"])
        self.assertEqual(child.sent, ["factory-secret", "automation", "shared-secret", "shared-secret"])

    def test_armbian_prompt_patterns(self):
        prompts = MODULE.DEFAULT_PROMPTS
        self.assertRegex("(current) UNIX password:", prompts["current_password"])
        self.assertRegex("Create root password:", prompts["new_password"])
        self.assertRegex("Create user (Jane) password:", prompts["new_password"])
        self.assertRegex("Repeat root password:", prompts["repeat_password"])
        self.assertRegex("Repeat user (Jane) password:", prompts["repeat_password"])
        self.assertRegex("Please provide a username (eg. your first name):", prompts["new_username"])
        self.assertRegex("Please provide your real name:", prompts["ignored_name"])
        self.assertRegex("Enter first name:", prompts["ignored_name"])
        self.assertRegex("Last name:", prompts["ignored_name"])
        self.assertRegex("Middle display name:", prompts["ignored_name"])
        self.assertNotRegex("Username:", prompts["ignored_name"])
        self.assertNotRegex("User name:", prompts["ignored_name"])

    def test_debug_session_redacts_passwords(self):
        result, _child = self.run_attempt(
            [
                (6, "factory-secret before ", "Password:"),
                (2, " new-secret echoed ", "New password:"),
                (0, "factory-secret new-secret user-secret ", MODULE.SUCCESS_MARKER),
            ],
            {"password": "new-secret", "user_password": "user-secret"},
            debug=True,
        )
        self.assertNotIn("factory-secret", result["session"])
        self.assertNotIn("new-secret", result["session"])
        self.assertNotIn("user-secret", result["session"])
        self.assertIn("********", result["session"])

    def test_password_is_not_in_process_arguments(self):
        command = MODULE._ssh_command("node.example", 2222, "root", "yes")
        self.assertNotIn("secret", command)
        self.assertIn("root@node.example", command)
        self.assertIn("-tt", command)
        self.assertIn("StrictHostKeyChecking=yes", command)


if __name__ == "__main__":
    unittest.main()
