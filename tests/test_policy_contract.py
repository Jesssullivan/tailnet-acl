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

    def test_operator_owns_node_exporter_egress_tag(self) -> None:
        owners = self.policy["tagOwners"]["tag:k8s-egress-nodeexporter"]
        self.assertIn("tag:k8s-operator", owners)

    def test_node_exporter_egress_grant_is_tcp_9100_and_host_scoped(self) -> None:
        expected = {
            "src": ["tag:k8s-egress-nodeexporter"],
            "dst": [
                "tinyland-relay-1",
                "tinyland-petting-zoo-mini",
                "tinyland-neo",
            ],
            "ip": ["tcp:9100"],
        }
        self.assertEqual(self.policy["grants"].count(expected), 1)

    def test_node_exporter_egress_targets_resolve_to_pinned_hosts(self) -> None:
        hosts = self.policy["hosts"]
        self.assertEqual(hosts["tinyland-relay-1"], "100.102.229.122")
        self.assertEqual(hosts["tinyland-petting-zoo-mini"], "100.111.5.80")
        self.assertEqual(hosts["tinyland-neo"], "100.67.93.34")

    def test_node_exporter_egress_tag_gets_no_broad_acl_access(self) -> None:
        """The dedicated egress tag must never appear as an ACL src.

        Reachability for these proxies is expressed only as a port-scoped
        grant; a bare ACL rule would widen it past tcp:9100.
        """
        srcs = [r["src"] for r in self.policy["acls"]]
        self.assertNotIn(["tag:k8s-egress-nodeexporter"], srcs)


if __name__ == "__main__":
    unittest.main()
