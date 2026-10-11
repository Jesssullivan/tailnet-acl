"""tailscale.com/cap/kubernetes contract (R-C557..R-C562, TIN-6192 thread 23587858).

Lane BZ's review of blahaj #2136 (TIN-6192 comment 789060b4, item 5): upstream
tailscale v1.102.4 addImpersonationHeaders fails open. When the caller's
kubernetes cap does not decode, the proxy logs the error and forwards the
request with no impersonation headers, as the operator ServiceAccount. Go's
decoder also ignores unknown keys, so a misspelled key yields an empty rule
and a tagged caller falls back to its tags as groups. scripts/kubernetes_cap.py
admits only a strict subset of upstream's KubernetesCapRule; these tests pin
the compiled policy to it, mutation-check the checker, and prove the build,
the trusted CI driver and the manual push refuse a violating candidate.
"""

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build  # noqa: E402
import kubernetes_cap  # noqa: E402
import policy_ci  # noqa: E402
import policy_source  # noqa: E402
import push  # noqa: E402
from policy_source import compile_revision, head_revision  # noqa: E402

CAP = "tailscale.com/cap/kubernetes"
LEGACY = "https://tailscale.com/cap/kubernetes"
CI_RULE = [{"impersonate": {"groups": ["adi-sms-deployers"]}}]

# json tags of kubetypes.KubernetesCapRule and ImpersonateRule at tailscale
# v1.102.4 (tag commit 3caf7d9e7dcaba589cfc58beda596929733e4fea,
# kube/kubetypes/grants.go). The contract admits a subset of these.
UPSTREAM_RULE_KEYS = {"impersonate", "recorder", "recorderAddrs", "enforceRecorder", "enableEvents"}
UPSTREAM_IMPERSONATE_KEYS = {"groups"}


def grant(app, src=("tag:tinyland-lab-ci-ephemeral",), dst=("tag:k8s-operator",)):
    return {"src": list(src), "dst": list(dst), "app": app, "ip": ["tcp:443"]}


def with_grant(policy, row):
    mutated = copy.deepcopy(policy)
    mutated["grants"].append(row)
    return mutated


class CompiledPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = compile_revision(head_revision())

    def test_head_policy_complies(self) -> None:
        self.assertEqual(kubernetes_cap.violations(self.policy), [])

    def test_legacy_name_appears_nowhere_in_head_policy(self) -> None:
        self.assertNotIn(LEGACY, json.dumps(self.policy).lower())

    def test_every_kubernetes_cap_value_has_the_admitted_shape(self) -> None:
        values = [row["app"][CAP] for row in self.policy["grants"] if CAP in row.get("app", {})]
        self.assertTrue(values)
        for value in values:
            for rule in value:
                self.assertEqual(set(rule), {"impersonate"})
                self.assertEqual(set(rule["impersonate"]), {"groups"})
                groups = rule["impersonate"]["groups"]
                self.assertTrue(groups)
                for group in groups:
                    self.assertIsInstance(group, str)
                    self.assertFalse(group.lower().startswith("system:"), group)

    def test_mutation_legacy_name_row_fails(self) -> None:
        problems = kubernetes_cap.violations(with_grant(self.policy, grant({LEGACY: CI_RULE})))
        self.assertTrue(any("legacy cap name" in p for p in problems), problems)

    def test_mutation_malformed_value_fails(self) -> None:
        # A string where upstream expects a list: json.Unmarshal fails, and
        # upstream would forward as the operator ServiceAccount.
        bad = [{"impersonate": {"groups": "adi-sms-deployers"}}]
        problems = kubernetes_cap.violations(with_grant(self.policy, grant({CAP: bad})))
        self.assertTrue(any("groups" in p for p in problems), problems)

    def test_mutation_misspelled_key_fails(self) -> None:
        bad = [{"impersonte": {"groups": ["adi-sms-deployers"]}}]
        self.assertTrue(kubernetes_cap.violations(with_grant(self.policy, grant({CAP: bad}))))


class CheckerTest(unittest.TestCase):
    def check(self, app, surface="grants"):
        row = grant(app) if surface == "grants" else {"target": ["tag:x"], "app": app}
        return kubernetes_cap.violations({"grants": [], "nodeAttrs": [], surface: [row]})

    def test_admitted_keys_are_a_subset_of_upstream(self) -> None:
        self.assertLessEqual({"impersonate"}, UPSTREAM_RULE_KEYS)
        self.assertLessEqual({"groups"}, UPSTREAM_IMPERSONATE_KEYS)
        self.assertEqual(kubernetes_cap.CAP, CAP)
        self.assertEqual(kubernetes_cap.LEGACY_CAP, LEGACY)

    def test_valid_values_pass(self) -> None:
        for value in (
            CI_RULE,
            [{"impersonate": {"groups": ["a", "b"]}}],
            [{"impersonate": {"groups": ["a"]}}, {"impersonate": {"groups": ["b"]}}],
        ):
            with self.subTest(value=value):
                self.assertEqual(self.check({CAP: value}), [])

    def test_policy_without_kubernetes_caps_passes(self) -> None:
        self.assertEqual(kubernetes_cap.violations({"grants": [{"src": ["a"], "dst": ["b"], "ip": ["*"]}]}), [])
        self.assertEqual(kubernetes_cap.violations({"acls": [1]}), [])

    def test_legacy_and_variant_names_fail(self) -> None:
        for name in (
            LEGACY,
            "HTTPS://tailscale.com/cap/kubernetes",
            "http://tailscale.com/cap/kubernetes",
            "Tailscale.com/cap/kubernetes",
            "tailscale.com/cap/kubernetes/",
            " tailscale.com/cap/kubernetes",
            "tailscale.com/cap/Kubernetes",
        ):
            with self.subTest(name=name):
                self.assertTrue(self.check({name: CI_RULE}))

    def test_legacy_name_fails_anywhere_in_the_policy(self) -> None:
        self.assertTrue(kubernetes_cap.violations({"hosts": {"x": LEGACY}}))
        self.assertTrue(self.check({LEGACY: CI_RULE}, surface="nodeAttrs"))

    def test_malformed_values_fail(self) -> None:
        cases = {
            "string value": "adi-sms-deployers",
            "object value": {"impersonate": {"groups": ["a"]}},
            "empty list": [],
            "null": None,
            "rule not object": ["adi-sms-deployers"],
            "empty rule": [{}],
            "misspelled impersonate": [{"impersonte": {"groups": ["a"]}}],
            "extra rule key": [{"impersonate": {"groups": ["a"]}, "recorder": ["tag:rec"]}],
            "recorder only": [{"recorder": ["tag:rec"]}],
            "control-populated recorderAddrs": [{"impersonate": {"groups": ["a"]}, "recorderAddrs": ["100.64.0.1:80"]}],
            "impersonate not object": [{"impersonate": ["a"]}],
            "impersonate list of rules": [{"impersonate": [{"groups": ["a"]}]}],
            "misspelled groups": [{"impersonate": {"group": ["a"]}}],
            "extra impersonate key": [{"impersonate": {"groups": ["a"], "users": ["u"]}}],
            "groups string": [{"impersonate": {"groups": "a"}}],
            "groups empty": [{"impersonate": {"groups": []}}],
            "groups null": [{"impersonate": {"groups": None}}],
            "group not string": [{"impersonate": {"groups": [1]}}],
            "group empty": [{"impersonate": {"groups": [""]}}],
            "group whitespace": [{"impersonate": {"groups": [" a"]}}],
            "system:masters": [{"impersonate": {"groups": ["system:masters"]}}],
            "System:Masters": [{"impersonate": {"groups": ["System:Masters"]}}],
            "system:authenticated": [{"impersonate": {"groups": ["system:authenticated"]}}],
            "system:serviceaccounts": [{"impersonate": {"groups": ["a", "system:serviceaccounts"]}}],
            "duplicate group": [{"impersonate": {"groups": ["a", "a"]}}],
        }
        for label, value in cases.items():
            with self.subTest(label):
                self.assertTrue(self.check({CAP: value}), label)

    def test_app_must_be_an_object(self) -> None:
        self.assertTrue(self.check([{CAP: CI_RULE}]))

    def test_problem_text_names_location(self) -> None:
        problems = self.check({CAP: [{"impersonate": {"groups": ["system:masters"]}}]})
        self.assertEqual(len(problems), 1)
        self.assertIn("grants[0]", problems[0])


class DhallRenderingTest(unittest.TestCase):
    """The typed Dhall surfaces cannot smuggle a violating value past the checker."""

    def render(self, caps: str) -> list:
        expr = f"""
let G = ./types/Grant.dhall
let J = ./types/JSON.dhall
in  G.render [ G.cap [ "tag:a" ] [ "tag:k8s-operator" ] [ {caps} ] ]
"""
        out = subprocess.run(
            ["dhall-to-json"], input=expr, capture_output=True, text=True, check=True, cwd=str(ROOT),
        ).stdout
        return json.loads(out)

    def test_typed_kubernetes_variant_renders_the_admitted_shape(self) -> None:
        grants = self.render('G.Cap.Kubernetes { impersonateGroups = [ "adi-sms-deployers" ] }')
        self.assertEqual(grants[0]["app"], {CAP: CI_RULE})
        self.assertEqual(kubernetes_cap.violations({"grants": grants}), [])

    def test_typed_variant_with_no_groups_fails(self) -> None:
        grants = self.render("G.Cap.Kubernetes { impersonateGroups = [] : List Text }")
        self.assertTrue(kubernetes_cap.violations({"grants": grants}))

    def test_typed_variant_with_system_masters_fails(self) -> None:
        grants = self.render('G.Cap.Kubernetes { impersonateGroups = [ "system:masters" ] }')
        self.assertTrue(kubernetes_cap.violations({"grants": grants}))

    def test_custom_escape_hatch_with_legacy_name_fails(self) -> None:
        grants = self.render(
            f'G.Cap.Custom {{ name = "{LEGACY}", json = J.array [ J.object [ {{ mapKey = "impersonate", '
            'mapValue = J.object [ { mapKey = "groups", mapValue = J.strings [ "adi-sms-deployers" ] } ] } ] ] }'
        )
        self.assertIn(LEGACY, grants[0]["app"])
        self.assertTrue(kubernetes_cap.violations({"grants": grants}))

    def test_custom_escape_hatch_with_malformed_value_fails(self) -> None:
        grants = self.render(
            f'G.Cap.Custom {{ name = "{CAP}", json = J.array [ J.object [ {{ mapKey = "impersonate", '
            'mapValue = J.object [ { mapKey = "groups", mapValue = J.string "adi-sms-deployers" } ] } ] ] }'
        )
        self.assertTrue(kubernetes_cap.violations({"grants": grants}))


BAD = {"grants": [grant({LEGACY: CI_RULE})], "acls": []}


class RefusalTest(unittest.TestCase):
    """Build, trusted driver and manual push each refuse a violating candidate."""

    def test_build_refuses_and_writes_nothing(self) -> None:
        policy = {k: ([] if k not in ("autoApprovers", "hosts", "groups", "tagOwners") else {})
                  for k in ("groups", "tagOwners", "acls", "grants", "ssh", "nodeAttrs", "autoApprovers", "hosts")}
        policy["grants"] = BAD["grants"]
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(policy), stderr="")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            build.subprocess, "run", return_value=completed
        ), mock.patch.object(build, "OUTPUT_DIR", Path(directory)), mock.patch.object(
            build, "OUTPUT_FILE", Path(directory) / "policy.json"
        ), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(build.main(), 1)
            self.assertFalse((Path(directory) / "policy.json").exists())
        self.assertIn("legacy cap name", err.getvalue())

    def test_trusted_driver_refuses_before_requesting_a_token(self) -> None:
        for role in ("reader", "writer"):
            with self.subTest(role=role), mock.patch.object(
                policy_ci, "trusted_context", return_value=("a" * 40, "b" * 40)
            ), mock.patch.object(policy_ci, "_run"), mock.patch.object(
                policy_ci, "compile_revision", side_effect=[{"acls": []}, BAD]
            ), mock.patch.object(policy_ci, "resolve_oidc") as oidc, mock.patch.object(
                policy_ci, "promote"
            ) as promote:
                with self.assertRaises(policy_source.PolicyError) as caught:
                    policy_ci.run(role)
                oidc.assert_not_called()
                promote.assert_not_called()
                self.assertNotIn(LEGACY, str(caught.exception))

    def test_manual_push_refuses_before_resolving_a_credential(self) -> None:
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["push.py", "--dry-run"]), mock.patch.object(
            push, "head_revision", return_value="c" * 40
        ), mock.patch.object(push, "compile_revision", return_value=BAD), mock.patch.object(
            push, "resolve_bearer"
        ) as bearer, mock.patch.object(push, "promote") as promote, contextlib.redirect_stdout(
            output
        ), contextlib.redirect_stderr(output):
            self.assertEqual(push.main(), 1)
        bearer.assert_not_called()
        promote.assert_not_called()
        self.assertIn("kubernetes capability", output.getvalue())


if __name__ == "__main__":
    unittest.main()
