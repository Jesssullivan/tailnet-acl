"""Validator response contracts and the reviewed split-identity workflow boundary."""

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import acl_validate  # noqa: E402


class ValidateResponseContractTest(unittest.TestCase):
    def test_empty_body_is_a_pass(self) -> None:
        ok, problems = acl_validate.interpret(200, "")
        self.assertTrue(ok)
        self.assertEqual(problems, [])

    def test_empty_object_is_a_pass(self) -> None:
        ok, problems = acl_validate.interpret(200, "{}")
        self.assertTrue(ok)
        self.assertEqual(problems, [])

    def test_message_on_http_200_is_a_failure(self) -> None:
        # The trap: Tailscale reports grammar errors with a 200 status.
        ok, problems = acl_validate.interpret(
            200, '{"message": "line 3, column 5: unknown action"}'
        )
        self.assertFalse(ok)
        self.assertEqual(problems, ["validation response contains a rejection message"])

    def test_data_errors_on_http_200_are_a_failure(self) -> None:
        ok, problems = acl_validate.interpret(
            200, '{"data": [{"user": "alice", "errors": ["cannot reach tag:x"]}]}'
        )
        self.assertFalse(ok)
        self.assertEqual(problems, ["validation response contains rejected checks"])

    def test_data_warnings_on_http_200_are_a_failure(self) -> None:
        # Parity with tailscale.com/cmd/gitops-pusher, which fails on any
        # non-empty data array.
        ok, problems = acl_validate.interpret(
            200, '{"data": [{"user": "bob", "warnings": ["unused group"]}]}'
        )
        self.assertFalse(ok)
        self.assertEqual(problems, ["validation response contains rejected checks"])

    def test_unauthorized_is_a_failure(self) -> None:
        ok, problems = acl_validate.interpret(401, '{"message": "API token invalid"}')
        self.assertFalse(ok)
        self.assertNotIn("API token invalid", problems)
        self.assertIn("HTTP 401", problems)

    def test_non_2xx_with_empty_body_is_still_a_failure(self) -> None:
        ok, problems = acl_validate.interpret(503, "")
        self.assertFalse(ok)
        self.assertEqual(problems, ["HTTP 503"])

    def test_unparseable_body_is_a_failure(self) -> None:
        ok, problems = acl_validate.interpret(200, "<html>gateway</html>")
        self.assertFalse(ok)
        self.assertTrue(any("unparseable" in p for p in problems))

    def test_known_bad_policy_is_actually_malformed(self) -> None:
        # --prove is only meaningful if the probe policy really is invalid.
        rule = acl_validate.KNOWN_BAD_POLICY["acls"][0]
        self.assertNotIn(rule["action"], {"accept", "check"})
        self.assertTrue(rule["src"][0].startswith("group:"))
        self.assertIn("undefined", rule["src"][0])


class ProveGateTest(unittest.TestCase):
    """The --prove self-test decides whether a clean result may be trusted."""

    def _run(self, responses: "list[tuple[int, str]]") -> "tuple[int, int]":
        calls = {"n": 0}

        def fake_post(_bearer: str, _policy: dict) -> "tuple[int, str]":
            response = responses[calls["n"]]
            calls["n"] += 1
            return response

        with mock.patch.object(acl_validate, "post_validate", fake_post), mock.patch.object(
            acl_validate, "resolve_bearer", lambda secret: "bearer"
        ), mock.patch.object(
            acl_validate, "compile_revision", return_value={"acls": []}
        ), mock.patch.object(
            acl_validate, "head_revision", return_value="a" * 40
        ), mock.patch.dict(
            os.environ, {"TAILSCALE_API_KEY": "tskey-api-stub"}, clear=False
        ), mock.patch.object(
            sys, "argv", ["acl_validate.py", "--prove"]
        ):
            return acl_validate.main(), calls["n"]

    def test_known_bad_rejected_then_real_policy_clean_passes(self) -> None:
        code, calls = self._run(
            [(200, '{"message": "group:... is not defined"}'), (200, "")]
        )
        self.assertEqual(code, 0)
        self.assertEqual(calls, 2)

    def test_known_bad_accepted_means_blind_and_fails(self) -> None:
        # The endpoint said a deliberately invalid policy is fine. A clean
        # result on the real policy would then be worthless.
        code, calls = self._run([(200, "{}")])
        self.assertEqual(code, 1)
        self.assertEqual(calls, 1, "must not go on to validate the real policy")

    def test_endpoint_absent_fails_without_grammar_proof(self) -> None:
        code, calls = self._run([(404, '{"message": "404 page not found"}')])
        self.assertEqual(code, 1)
        self.assertEqual(calls, 1)

    def test_malformed_self_test_response_does_not_prove_rejection(self) -> None:
        code, calls = self._run([(200, "<html>gateway</html>")])
        self.assertEqual(code, 1)
        self.assertEqual(calls, 1)

    def test_rejection_message_does_not_mask_malformed_self_test_data(self) -> None:
        code, calls = self._run([(200, '{"message":"rejected", "data":false}')])
        self.assertEqual(code, 1)
        self.assertEqual(calls, 1)

    def test_malformed_utf8_canary_does_not_reach_candidate_validation(self) -> None:
        code, calls = self._run([(200, b'{"message":"\xff"}')])
        self.assertEqual(code, 1)
        self.assertEqual(calls, 1)

    def test_auth_failure_during_self_test_fails(self) -> None:
        code, calls = self._run([(401, '{"message": "API token invalid"}')])
        self.assertEqual(code, 1)
        self.assertEqual(calls, 1)

    def test_real_policy_rejection_fails(self) -> None:
        code, calls = self._run(
            [
                (200, '{"message": "unknown action"}'),
                (200, '{"message": "line 12, column 3: tag:nope is not defined"}'),
            ]
        )
        self.assertEqual(code, 1)
        self.assertEqual(calls, 2)


class WorkflowScopeTest(unittest.TestCase):
    def test_unprivileged_ci_cannot_request_oidc_or_access_production(self):
        text = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
        for forbidden in ("environment:", "id-token:", "pull-requests: write", "TAILSCALE_API_KEY", "upload-artifact"):
            self.assertNotIn(forbidden, text)
        self.assertIn("nix develop --command just test", text)

    def test_trusted_workflows_pin_main_code_and_separate_variables(self):
        for name, role in (("policy-validate.yml", "READER"), ("cd.yml", "WRITER")):
            with self.subTest(name=name):
                text = (REPO_ROOT / ".github/workflows" / name).read_text()
                self.assertIn("environment: production", text)
                self.assertIn("id-token: write", text)
                self.assertIn("ref: ${{ github.workflow_sha }}", text)
                self.assertIn("persist-credentials: false", text)
                self.assertIn("vars.TS_POLICY_" + role + "_CLIENT_ID", text)
                self.assertIn("vars.TS_POLICY_" + role + "_AUDIENCE", text)
                self.assertIn("scripts/policy_ci.py " + role.lower(), text)
                for forbidden in ("secrets.", "@main", "magic-nix-cache", "upload-artifact", "download-artifact", "pull_request.head.sha", "pull-requests: write"):
                    self.assertNotIn(forbidden, text)
                for action in re.findall(r"uses: (\S+)", text):
                    self.assertRegex(action, r"@[0-9a-f]{40}$")

    def test_reader_rejects_fork_job_before_any_oidc_capability(self):
        text = (REPO_ROOT / ".github/workflows/policy-validate.yml").read_text()
        self.assertIn("pull_request_target:", text)
        for clause in ("github.repository_id == '1165961732'", "github.repository_owner_id == '37297218'", "github.event.pull_request.head.repo.id == 1165961732", "github.event.pull_request.base.repo.id == 1165961732", "github.event.pull_request.base.ref == 'main'"):
            self.assertIn(clause, text)
        self.assertLess(text.index("    if:"), text.index("      id-token: write"))


if __name__ == "__main__":
    unittest.main()
