import json
import subprocess
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from models import ActionRequest
from tools.sandbox_executor import execute_in_sandbox


class SandboxRunnerTests(unittest.TestCase):
    def make_request(self, action="preview", resource="demo", records=0):
        return ActionRequest(
            agent="customer_support_bot",
            user="customer_support_bot",
            tool="demo",
            action=action,
            resource=resource,
            environment="development",
            records=records,
        )

    @patch("tools.sandbox_executor.subprocess.run")
    @patch("tools.sandbox_executor.check_action_policy")
    @patch("tools.sandbox_executor.SANDBOX_URL", None)
    def test_policy_approved_action_builds_hardened_docker_command(
        self, check_policy, run
    ):
        check_policy.return_value = {"decision": "SANDBOX"}
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({
                "status": "SIMULATED",
                "executed": True,
                "isolation": "docker-no-network-readonly",
            }),
            stderr="",
        )

        result = execute_in_sandbox(self.make_request())

        self.assertEqual(result["status"], "SIMULATED")
        self.assertTrue(result["executed"])
        self.assertEqual(result["isolation"], "docker-no-network-readonly")
        command = run.call_args.args[0]
        self.assertIn("--network=none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges", command)
        check_policy.assert_called_once()

    @patch("tools.sandbox_executor.subprocess.run")
    @patch("tools.sandbox_executor.check_action_policy")
    @patch("tools.sandbox_executor.SANDBOX_URL", None)
    def test_unregistered_actions_are_rejected_before_runner_dispatch(
        self, check_policy, run
    ):
        check_policy.return_value = {"decision": "SANDBOX"}

        for request in (
            self.make_request(action="shell"),
            self.make_request(resource="customer"),
        ):
            with self.subTest(request=request), self.assertRaises(PermissionError):
                execute_in_sandbox(request)

        run.assert_not_called()

    @patch("tools.sandbox_executor.subprocess.run")
    @patch("tools.sandbox_executor.check_action_policy")
    @patch("tools.sandbox_executor.SANDBOX_URL", None)
    def test_policy_block_prevents_runner_dispatch(self, check_policy, run):
        check_policy.return_value = {"decision": "BLOCK"}

        with self.assertRaises(PermissionError):
            execute_in_sandbox(self.make_request())

        run.assert_not_called()
        check_policy.assert_called_once()

    def test_negative_record_count_fails_request_validation(self):
        with self.assertRaises(ValidationError):
            self.make_request(records=-1)


if __name__ == "__main__":
    unittest.main()
