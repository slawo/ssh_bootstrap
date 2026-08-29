"""Unit tests for bootstrap workflow orchestration."""

from pathlib import Path
import importlib.util
import unittest


HELPER = Path(__file__).parents[2] / "plugins" / "plugin_utils" / "_workflow.py"
SPEC = importlib.util.spec_from_file_location("workflow_helper", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class QueueCallable:
    def __init__(self, values):
        self.values = iter(values)
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return next(self.values)


class WorkflowTests(unittest.TestCase):
    def config(self, install_sudo=True, return_password=False):
        return {
            "onboarding": {"username": "automation", "password": "user-secret", "passwordless_sudo": True},
            "root": {"username": "root", "password": "root-secret", "login": True, "disable_after_onboarding": False},
            "install_sudo": install_sudo,
            "return_password": return_password,
        }

    def candidates(self):
        return [
            {"username": "automation", "password": "user-secret", "source": "onboarding"},
            {"username": "root", "password": "root-secret", "source": "root"},
            {"username": "root", "password": "factory-secret", "source": "credentials"},
        ]

    def execute(self, probe_values, **overrides):
        dependencies = {
            "run_command": overrides.get("run_command", QueueCallable([])),
            "run_script": overrides.get("run_script", QueueCallable([])),
            "probe_access": QueueCallable(probe_values),
            "detect_platform": overrides.get("detect_platform", QueueCallable([])),
            "sudo_install_command": lambda platform: "install sudo",
            "build_provision_script": lambda **kwargs: "provision user",
        }
        result = MODULE.execute_workflow(
            workflow=overrides.get("workflow", self.config()),
            candidates=self.candidates(),
            connection_base={"host": "node", "port": 22, "host_key_checking": "yes", "timeout": 5},
            **dependencies,
        )
        return result, dependencies

    def test_existing_onboarded_sudoer_returns_without_password(self):
        access = {"success": True, "uid": 1000, "is_root": False, "sudo_available": True, "can_become": True}
        result, _deps = self.execute([access])
        self.assertFalse(result["changed"])
        self.assertNotIn("password", result["credentials"])
        self.assertEqual(result["become"], {"enabled": True, "method": "sudo", "user": "root"})

    def test_unprivileged_login_is_skipped_before_root(self):
        unprivileged = {"success": True, "uid": 1000, "is_root": False, "sudo_available": False, "can_become": False}
        root = {"success": True, "uid": 0, "is_root": True, "sudo_available": True, "can_become": True}
        verified = {"success": True, "uid": 1000, "is_root": False, "sudo_available": True, "can_become": True}
        result, _deps = self.execute(
            [unprivileged, root, verified],
            detect_platform=QueueCallable([{"success": True, "family": "debian", "package_manager": "apt"}]),
            run_script=QueueCallable([{"success": True, "rc": 0}]),
        )
        self.assertTrue(result["changed"])
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(result["credentials"]["username"], "automation")

    def test_default_list_password_is_always_returned(self):
        workflow = self.config()
        workflow["onboarding"] = {"username": None, "password": None, "passwordless_sudo": True}
        failures = [{"success": False, "reason": "rejected"}, {"success": False, "reason": "rejected"}]
        root = {"success": True, "uid": 0, "is_root": True, "sudo_available": False, "can_become": True}
        result, _deps = self.execute([*failures, root], workflow=workflow)
        self.assertEqual(result["credentials"]["password"], "factory-secret")

    def test_install_sudo_false_returns_privileged_password(self):
        root = {"success": True, "uid": 0, "is_root": True, "sudo_available": False, "can_become": True}
        result, _deps = self.execute(
            [{"success": False, "reason": "rejected"}, root],
            workflow=self.config(install_sudo=False),
            detect_platform=QueueCallable([{"success": True, "family": "debian", "package_manager": "apt"}]),
        )
        self.assertEqual(result["credentials"]["password"], "root-secret")

    def test_sudo_install_and_provisioning_use_streamed_privileged_scripts(self):
        root = {"success": True, "uid": 0, "is_root": True, "sudo_available": False, "can_become": True}
        verified = {"success": True, "uid": 1000, "is_root": False, "sudo_available": True, "can_become": True}
        scripts = QueueCallable([{"success": True, "rc": 0}, {"success": True, "rc": 0}])
        result, _deps = self.execute(
            [{"success": False, "reason": "rejected"}, root, verified],
            detect_platform=QueueCallable([{"success": True, "family": "debian", "package_manager": "apt"}]),
            run_script=scripts,
        )
        self.assertTrue(result["success"])
        self.assertEqual(len(scripts.calls), 2)
        self.assertEqual(scripts.calls[0][1]["script"], "install sudo")
        self.assertFalse(scripts.calls[0][1]["become"])
        self.assertEqual(scripts.calls[1][1]["script"], "provision user")

    def test_failed_post_provision_sudo_verification_fails(self):
        root = {"success": True, "uid": 0, "is_root": True, "sudo_available": True, "can_become": True}
        bad_user = {"success": True, "uid": 1000, "is_root": False, "sudo_available": True, "can_become": False}
        result, _deps = self.execute(
            [{"success": False, "reason": "rejected"}, root, bad_user],
            detect_platform=QueueCallable([{"success": True, "family": "debian", "package_manager": "apt"}]),
            run_script=QueueCallable([{"success": True, "rc": 0}]),
        )
        self.assertFalse(result["success"])
        self.assertTrue(result["changed"])


if __name__ == "__main__":
    unittest.main()
