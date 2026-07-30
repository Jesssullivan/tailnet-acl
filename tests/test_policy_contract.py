import ipaddress
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

    def test_kubernetes_operator_owns_rke2_egress_tag(self) -> None:
        owners = self.policy["tagOwners"]["tag:rke2-egress"]
        self.assertEqual(
            owners,
            [
                "tag:k8s-operator",
                "autogroup:admin",
                "group:dollhouse-admins",
            ],
        )

    def test_rke2_egress_authority_is_exact(self) -> None:
        expected = {
            "src": ["tag:rke2-egress"],
            "dst": ["tinyland-honey"],
            "ip": ["tcp:6443", "tcp:9345"],
        }
        related_grants = [
            grant
            for grant in self.policy["grants"]
            if "tag:rke2-egress" in grant.get("src", [])
            or "tag:rke2-egress" in grant.get("dst", [])
        ]
        self.assertEqual(related_grants, [expected])

        related_acls = [
            rule
            for rule in self.policy["acls"]
            if any("tag:rke2-egress" in value for value in rule["src"] + rule["dst"])
        ]
        self.assertEqual(related_acls, [])
        for section in ("ssh", "nodeAttrs", "autoApprovers"):
            self.assertNotIn(
                "tag:rke2-egress",
                json.dumps(self.policy[section], sort_keys=True),
            )

        self.assertEqual(self.policy["hosts"]["tinyland-honey"], "100.113.89.12")

    def test_no_parallel_direct_rule_reaches_honey_control_plane(self) -> None:
        expected = {
            "src": ["tag:rke2-egress"],
            "dst": ["tinyland-honey"],
            "ip": ["tcp:6443", "tcp:9345"],
        }
        honey_ip = ipaddress.ip_address(self.policy["hosts"]["tinyland-honey"])

        def destination_includes_honey(destination: str) -> bool:
            if destination in {"tinyland-honey", str(honey_ip), "*"}:
                return True
            try:
                return honey_ip in ipaddress.ip_network(destination, strict=False)
            except ValueError:
                return False

        self.assertTrue(destination_includes_honey("*"))
        self.assertTrue(destination_includes_honey("100.64.0.0/10"))
        direct_grants = [
            grant
            for grant in self.policy["grants"]
            if any(
                destination_includes_honey(dst)
                for dst in grant.get("dst", [])
            )
        ]
        self.assertEqual(direct_grants, [expected])

        def includes_control_plane_port(port_specification: str) -> bool:
            for item in port_specification.split(","):
                if item == "*":
                    return True
                if "-" in item:
                    start, end = item.split("-", 1)
                    if start.isdigit() and end.isdigit():
                        if any(
                            int(start) <= port <= int(end)
                            for port in (6443, 9345)
                        ):
                            return True
                elif item.isdigit() and int(item) in {6443, 9345}:
                    return True
            return False

        self.assertTrue(includes_control_plane_port("*"))
        self.assertTrue(includes_control_plane_port("6000-10000"))
        self.assertTrue(includes_control_plane_port("22,6443"))
        direct_legacy_rules = []
        for rule in self.policy["acls"]:
            for destination in rule["dst"]:
                host, separator, port = destination.rpartition(":")
                if (
                    separator
                    and destination_includes_honey(host)
                    and includes_control_plane_port(port)
                ):
                    direct_legacy_rules.append(rule)
                    break
        self.assertEqual(direct_legacy_rules, [])


if __name__ == "__main__":
    unittest.main()
