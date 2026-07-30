import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
CI = WORKFLOW_DIR / "ci.yml"
CD = WORKFLOW_DIR / "cd.yml"
PUBLISH = WORKFLOW_DIR / "publish-acl.yml"
JUSTFILE = ROOT / "justfile"
PUBLICATION_DOC = ROOT / "docs" / "acl-publication-authority.md"

HOSTED_LABEL = re.compile(r"\b(?:ubuntu|macos|windows)-", re.IGNORECASE)
RUNNER = re.compile(r"(?m)^\s*runs-on:\s*(\S+)\s*$")
ACTION_REF = re.compile(r"(?m)^\s*-\s+uses:\s+[^@\s]+@([^\s#]+)")


def workflow_paths() -> list[Path]:
    return sorted(
        set(WORKFLOW_DIR.glob("*.yml")) | set(WORKFLOW_DIR.glob("*.yaml"))
    )


class WorkflowAuthorityTest(unittest.TestCase):
    def test_all_workflows_use_only_sanctioned_runners(self) -> None:
        for path in workflow_paths():
            source = path.read_text(encoding="utf-8")
            self.assertIsNone(HOSTED_LABEL.search(source), path.name)
            runners = RUNNER.findall(source)
            self.assertTrue(runners, path.name)
            self.assertTrue(
                all(label.startswith("tinyland-") for label in runners),
                f"{path.name}: {runners}",
            )

    def test_source_ci_is_credential_free_and_non_mutating(self) -> None:
        source = CI.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^  pull_request:")
        self.assertRegex(source, r"(?m)^  push:")
        self.assertNotIn("workflow_dispatch:", source)
        self.assertNotIn("secrets.", source)
        self.assertNotIn("environment:", source)
        self.assertNotIn("scripts/push.py", source)
        self.assertNotIn("scripts/validate.py", source)
        self.assertNotRegex(source, r"(?m)^\s+\w[\w-]*:\s+write\s*$")

    def test_old_cd_identity_is_a_non_mutating_tombstone(self) -> None:
        source = CD.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^  workflow_dispatch:")
        self.assertNotRegex(
            source,
            r"(?m)^  (?:push|pull_request|pull_request_target|schedule):",
        )
        self.assertIn("permissions: {}", source)
        self.assertNotIn("uses:", source)
        self.assertNotIn("secrets.", source)
        self.assertNotIn("environment:", source)
        self.assertNotIn("scripts/push.py", source)
        self.assertNotIn("scripts/validate.py", source)

    def test_publish_is_exact_dispatch_only_authority(self) -> None:
        source = PUBLISH.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^  workflow_dispatch:")
        self.assertNotRegex(
            source,
            r"(?m)^  (?:push|pull_request|pull_request_target|schedule):",
        )
        self.assertEqual(source.count("environment: tailnet-acl-production"), 2)
        self.assertIn('github.event_name == "workflow_dispatch"', source.replace("'", '"'))
        self.assertIn('"refs/heads/main"', source.replace("'", '"'))
        self.assertIn("${{ github.sha }}", source)
        self.assertIn("${{ github.run_attempt }}", source)
        self.assertIn('[ "${RUN_ATTEMPT}" != "1" ]', source)
        self.assertIn("expected_source_sha:", source)
        self.assertIn("expected_live_policy_sha256:", source)
        self.assertIn("expected_policy_sha256:", source)
        self.assertIn("plan-tailnet-acl-${EXPECTED_SOURCE_SHA}", source)
        self.assertIn("apply-tailnet-acl-${EXPECTED_SOURCE_SHA}", source)
        self.assertEqual(source.count("ref: main"), 2)
        self.assertEqual(
            source.count('test "$(git rev-parse HEAD)" = "${EXPECTED_SOURCE_SHA}"'),
            2,
        )

        validator = source.split("\n  plan:", 1)[0]
        self.assertNotIn("secrets.", validator)
        self.assertNotIn("environment:", validator)

        plan = source.split("\n  plan:", 1)[1].split("\n  apply:", 1)[0]
        self.assertIn("--dry-run", plan)
        self.assertNotIn("--confirm", plan)
        self.assertIn(
            "secrets.TAILSCALE_ACL_READ_OAUTH_CLIENT_SECRET",
            plan,
        )
        self.assertIn("vars.TAILSCALE_ACL_READ_OAUTH_CLIENT_ID", plan)
        self.assertNotIn("TAILSCALE_ACL_WRITE_", plan)
        self.assertIn('--source-sha "${EXPECTED_SOURCE_SHA}"', plan)

        apply = source.split("\n  apply:", 1)[1]
        self.assertIn("--confirm", apply)
        self.assertIn("--expect-live-sha256", apply)
        self.assertIn("--expect-policy-sha256", apply)
        self.assertIn(
            "secrets.TAILSCALE_ACL_WRITE_OAUTH_CLIENT_SECRET",
            apply,
        )
        self.assertIn("vars.TAILSCALE_ACL_WRITE_OAUTH_CLIENT_ID", apply)
        self.assertNotIn("TAILSCALE_ACL_READ_", apply)
        self.assertIn('--source-sha "${EXPECTED_SOURCE_SHA}"', apply)

        self.assertNotIn("TAILSCALE_ACL_OAUTH_CLIENT_SECRET", source)
        self.assertNotIn("TAILSCALE_ACL_OAUTH_CLIENT_ID", source)
        self.assertNotIn("secrets.TAILSCALE_API_KEY", source)
        self.assertNotIn("secrets.GITHUB_TOKEN", source)

    def test_external_actions_are_immutable(self) -> None:
        for path in workflow_paths():
            refs = ACTION_REF.findall(path.read_text(encoding="utf-8"))
            self.assertTrue(
                all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs),
                f"{path.name}: {refs}",
            )

    def test_operator_push_recipe_requires_durable_source_bound_receipt(
        self,
    ) -> None:
        source = JUSTFILE.read_text(encoding="utf-8")
        push = source.split("\npush: build\n", 1)[1].split("\n\n", 1)[0]
        self.assertIn("--confirm", push)
        self.assertIn('--source-sha "${SOURCE_SHA:?required}"', push)
        self.assertIn('--receipt "${RECEIPT:?required}"', push)

    def test_new_workflow_identity_check_is_post_landing(self) -> None:
        source = PUBLICATION_DOC.read_text(encoding="utf-8")
        pre_landing, post_landing = source.split(
            "## Post-landing, pre-dispatch barrier",
            1,
        )
        self.assertIn("Permanently disable historical", pre_landing)
        self.assertNotIn("new workflow's exact numeric ID", pre_landing)
        self.assertIn("new workflow's exact numeric ID", post_landing)
        self.assertIn("238207465", post_landing)


if __name__ == "__main__":
    unittest.main()
