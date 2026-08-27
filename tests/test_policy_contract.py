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

    def test_voters_reach_pyroscope_ingest_port_scoped(self) -> None:
        """All three voters may push profiles, and only to tcp/4040.

        Mirrors the loki-observability rule: an explicit, port-scoped
        host-alias rule rather than a tag widening. Before this rule only
        sting could reach the ingest (measured 2026-08-27: /ready 200 from
        sting, 000 from honey and bumble), which is what kept host
        profiling dark on two of three voters (blahaj host_profiling
        mechanism, estate O6 lane).
        """
        expected = {
            "action": "accept",
            "src": ["tinyland-honey", "tinyland-bumble", "tinyland-sting"],
            "dst": ["tinyland-pyroscope-observability:4040"],
        }
        self.assertEqual(self.policy["acls"].count(expected), 1)

    def test_pyroscope_ingest_resolves_to_pinned_host(self) -> None:
        hosts = self.policy["hosts"]
        self.assertEqual(hosts["tinyland-pyroscope-observability"], "100.87.88.47")

    def test_pyroscope_ingest_has_no_wildcard_port_rule(self) -> None:
        """No rule may open the pyroscope ingest device beyond tcp/4040."""
        for rule in self.policy["acls"]:
            for dst in rule["dst"]:
                if dst.startswith("tinyland-pyroscope-observability"):
                    self.assertEqual(
                        dst, "tinyland-pyroscope-observability:4040"
                    )


if __name__ == "__main__":
    unittest.main()
