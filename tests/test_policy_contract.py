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

    def test_gf_reapi_route_tags_have_exact_owners(self) -> None:
        self.assertCountEqual(
            self.policy["tagOwners"]["tag:gf-reapi-cell-egress"],
            [
                "tag:k8s-operator",
                "autogroup:admin",
                "group:dollhouse-admins",
            ],
        )
        self.assertCountEqual(
            self.policy["tagOwners"]["tag:gf-reapi-darwin-worker"],
            [
                "tag:tag-authority",
                "autogroup:admin",
                "group:dollhouse-admins",
            ],
        )
        self.assertNotIn(
            "tag:k8s-operator",
            self.policy["tagOwners"]["tag:gf-reapi-darwin-worker"],
        )

    def test_gf_reapi_darwin_route_is_single_port_and_tag_scoped(self) -> None:
        expected = {
            "src": ["tag:gf-reapi-cell-egress"],
            "dst": ["tag:gf-reapi-darwin-worker"],
            "ip": ["tcp:8981"],
        }
        route_tags = {
            "tag:gf-reapi-cell-egress",
            "tag:gf-reapi-darwin-worker",
        }
        references = []
        for surface in ("acls", "grants"):
            for rule in self.policy[surface]:
                endpoints = [
                    endpoint
                    for key in ("src", "dst")
                    for endpoint in rule.get(key, [])
                ]
                if any(
                    endpoint == tag or endpoint.startswith(f"{tag}:")
                    for endpoint in endpoints
                    for tag in route_tags
                ):
                    references.append((surface, rule))

        self.assertEqual(references, [("grants", expected)])


if __name__ == "__main__":
    unittest.main()
