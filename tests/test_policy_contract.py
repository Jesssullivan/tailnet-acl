import json
import unittest
from pathlib import Path


POLICY = Path(__file__).resolve().parents[1] / "generated" / "policy.json"


class PolicyContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(POLICY.read_text(encoding="utf-8"))

    def test_kubernetes_operator_owns_mcp_proxy_tag(self) -> None:
        owners = self.policy["tagOwners"]["tag:mcp-proxy"]
        self.assertIn("tag:k8s-operator", owners)

    def test_honey_mcp_access_is_tcp_only_and_tag_scoped(self) -> None:
        expected = {
            "src": ["tinyland-honey"],
            "dst": ["tag:mcp-proxy"],
            "ip": ["tcp:8080"],
        }
        self.assertEqual(self.policy["grants"].count(expected), 1)

    def test_honey_does_not_receive_broad_kubernetes_acl_access(self) -> None:
        broad_rule = {
            "action": "accept",
            "src": ["tinyland-honey"],
            "dst": ["tag:k8s:8080"],
        }
        self.assertNotIn(broad_rule, self.policy["acls"])

    def test_exporter_egress_identity_has_only_the_three_tcp_metrics_targets(self) -> None:
        tag = "tag:k8s-egress-nodeexporter"
        self.assertEqual(
            self.policy["tagOwners"][tag],
            ["tag:k8s-operator", "autogroup:admin", "group:dollhouse-admins"],
        )
        self.assertEqual(
            [grant for grant in self.policy["grants"] if tag in grant["src"]],
            [{"src": [tag], "dst": ["tinyland-relay-1", "tinyland-petting-zoo-mini", "tinyland-neo"], "ip": ["tcp:9100"]}],
        )
        self.assertFalse(any(tag in rule["src"] for rule in self.policy["acls"]))
        for name, address in {
            "tinyland-relay-1": "100.102.229.122",
            "tinyland-petting-zoo-mini": "100.111.5.80",
            "tinyland-neo": "100.67.93.34",
        }.items():
            self.assertEqual(self.policy["hosts"][name], address)


if __name__ == "__main__":
    unittest.main()
