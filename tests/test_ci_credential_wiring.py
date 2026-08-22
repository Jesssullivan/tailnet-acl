"""Contract tests for the CI/CD credential wiring.

Two things are pinned here:

1.  The response contract of Tailscale's ``POST /acl/validate`` endpoint, which
    reports policy errors with **HTTP 200**. A status-code check alone passes
    everything, so ``acl_validate.interpret`` is the load-bearing logic and it
    cannot be exercised live from a test.
2.  That ``validate`` (ci.yml) and ``deploy`` (cd.yml) read their credentials
    from one scope and one variable set. Splitting them again is the specific
    regression this repo already suffered.
"""

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
        self.assertIn("line 3, column 5: unknown action", problems)

    def test_data_errors_on_http_200_are_a_failure(self) -> None:
        ok, problems = acl_validate.interpret(
            200, '{"data": [{"user": "alice", "errors": ["cannot reach tag:x"]}]}'
        )
        self.assertFalse(ok)
        self.assertIn("user alice: error: cannot reach tag:x", problems)

    def test_data_warnings_on_http_200_are_a_failure(self) -> None:
        # Parity with tailscale.com/cmd/gitops-pusher, which fails on any
        # non-empty data array.
        ok, problems = acl_validate.interpret(
            200, '{"data": [{"user": "bob", "warnings": ["unused group"]}]}'
        )
        self.assertFalse(ok)
        self.assertIn("user bob: warning: unused group", problems)

    def test_unauthorized_is_a_failure(self) -> None:
        ok, problems = acl_validate.interpret(401, '{"message": "API token invalid"}')
        self.assertFalse(ok)
        self.assertIn("API token invalid", problems)
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

        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.json"
            policy_path.write_text(json.dumps({"acls": []}), encoding="utf-8")
            with mock.patch.object(acl_validate, "post_validate", fake_post), mock.patch.object(
                acl_validate, "resolve_bearer", lambda secret: "bearer"
            ), mock.patch.object(
                acl_validate, "GENERATED_POLICY", policy_path
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

    def test_endpoint_absent_skips_without_failing(self) -> None:
        code, calls = self._run([(404, '{"message": "404 page not found"}')])
        self.assertEqual(code, 0)
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
    CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    CD = REPO_ROOT / ".github" / "workflows" / "cd.yml"

    @classmethod
    def setUpClass(cls) -> None:
        cls.ci_text = cls.CI.read_text(encoding="utf-8")
        cls.cd_text = cls.CD.read_text(encoding="utf-8")

    def test_both_jobs_declare_the_production_environment(self) -> None:
        for name, text in (("ci.yml", self.ci_text), ("cd.yml", self.cd_text)):
            with self.subTest(workflow=name):
                self.assertIn("environment: production", text)

    def test_both_jobs_map_the_same_credential_pair(self) -> None:
        secret = "TAILSCALE_API_KEY: ${{ secrets.TAILSCALE_API_KEY }}"
        client_id = "TS_OAUTH_CLIENT_ID: ${{ vars.TS_OAUTH_CLIENT_ID }}"
        for name, text in (("ci.yml", self.ci_text), ("cd.yml", self.cd_text)):
            with self.subTest(workflow=name):
                self.assertIn(secret, text)
                self.assertIn(client_id, text)

    def test_credentials_are_mapped_exactly_once_per_workflow(self) -> None:
        # Job-level env only. A per-step remap is how the two scopes drifted
        # apart in the first place.
        for name, text in (("ci.yml", self.ci_text), ("cd.yml", self.cd_text)):
            with self.subTest(workflow=name):
                self.assertEqual(
                    len(re.findall(r"secrets\.TAILSCALE_API_KEY", text)), 1
                )
                self.assertEqual(
                    len(re.findall(r"vars\.TS_OAUTH_CLIENT_ID", text)), 1
                )

    def test_preflight_runs_in_both_workflows(self) -> None:
        for name, text in (("ci.yml", self.ci_text), ("cd.yml", self.cd_text)):
            with self.subTest(workflow=name):
                self.assertIn("scripts/ci_preflight.py", text)

    def test_server_side_validation_runs_with_prove_in_both_workflows(self) -> None:
        for name, text in (("ci.yml", self.ci_text), ("cd.yml", self.cd_text)):
            with self.subTest(workflow=name):
                self.assertIn("scripts/acl_validate.py --prove", text)

    def test_preflight_scope_string_matches_the_declared_environment(self) -> None:
        import ci_preflight

        self.assertIn("production", ci_preflight.SCOPE)


if __name__ == "__main__":
    unittest.main()
