import unittest
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from policy_source import compile_revision, head_revision


class PolicyContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = compile_revision(head_revision())

    def test_anonymous_gateway_is_a_separate_internet_only_identity(self) -> None:
        tag = "tag:anon-gateway"
        self.assertEqual(self.policy["tagOwners"][tag], ["autogroup:admin"])
        self.assertEqual(
            [row for row in self.policy["nodeAttrs"] if "mullvad" in row["attr"]],
            [{"target": [tag], "attr": ["mullvad"]}],
        )
        self.assertEqual(
            [row for row in self.policy["acls"] if tag in row["src"]],
            [{"action": "accept", "src": [tag], "dst": ["autogroup:internet:*"]}],
        )
        self.assertFalse(any(tag in row["src"] for row in self.policy["grants"]))
        self.assertFalse(any(tag in row["src"] or tag in row["dst"] for row in self.policy["ssh"]))
        self.assertNotIn(tag, self.policy["autoApprovers"]["exitNode"])
        self.assertFalse(any(tag in tags for tags in self.policy["autoApprovers"]["routes"].values()))
        # Additive policy has no deny override. Universal source rules would
        # silently grant this newly tagged node access beyond its explicit ACL.
        universal = {"*", "autogroup:tagged", "0.0.0.0/0", "::/0", "100.64.0.0/10"}
        for row in self.policy["acls"] + self.policy["grants"]:
            self.assertFalse(universal.intersection(row["src"]))

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

    def test_honey_interim_mcp_proxy_host_grant_is_exact(self) -> None:
        # lab TIN-4415 (2026-09-19): the five mcp-services proxies carry
        # tag:k8s only (blahaj never applied tag:mcp-proxy), so the tag-scoped
        # grant above matches nothing live. This host-alias grant is the
        # interim; it names exactly the five proxies and tcp/8080, nothing
        # wider, and is retired with them once the tag is applied.
        aliases = [
            "tinyland-mcp-arxiv",
            "tinyland-mcp-duckduckgo",
            "tinyland-mcp-fetch",
            "tinyland-mcp-paper-search",
            "tinyland-mcp-wikipedia",
        ]
        for alias in aliases:
            self.assertIn(alias, self.policy["hosts"])
        expected = {"src": ["tinyland-honey"], "dst": aliases, "ip": ["tcp:8080"]}
        self.assertEqual(self.policy["grants"].count(expected), 1)

    def test_honey_does_not_receive_broad_kubernetes_acl_access(self) -> None:
        broad_rule = {
            "action": "accept",
            "src": ["tinyland-honey"],
            "dst": ["tag:k8s:8080"],
        }
        self.assertNotIn(broad_rule, self.policy["acls"])

    # TIN-4670: raw Loki (3100) and Tempo (3200) on the observability proxies
    # are read only by group:dollhouse-admins and tag:mcp-proxy; Grafana stays
    # the human surface. The proxies carry tag:mcp-proxy alone (operator-side
    # retag), so no tag:k8s:* rule matches them. Policy is additive, so these
    # tests pin every rule that can reach tag:mcp-proxy.
    OBSERVABILITY_READ_GRANT = {
        "src": ["group:dollhouse-admins", "tag:mcp-proxy"],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:3100", "tcp:3200"],
    }
    LOKI_WRITER_GRANT = {
        "src": ["tinyland-honey", "tinyland-bumble", "tinyland-sting"],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:3100"],
    }
    HONEY_MCP_GRANT = {
        "src": ["tinyland-honey"],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:8080"],
    }
    # TIN-4686 PROBE: one off-cluster client (neo) gets a device-level grant
    # to tag:mcp-proxy on the Grafana (3000) and OTLP (4318) ports only, to
    # test whether that delivers the o11y Service host as a peer. A probe,
    # not the final shape: widened to the OTLP/Grafana source sets only if
    # it works, removed if it does not.
    NEO_O11Y_PROBE_GRANT = {
        "src": ["tinyland-neo"],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:3000", "tcp:4318"],
    }
    MCP_PROXY_GRANTS = [
        HONEY_MCP_GRANT,
        OBSERVABILITY_READ_GRANT,
        LOKI_WRITER_GRANT,
        NEO_O11Y_PROBE_GRANT,
    ]

    def test_neo_o11y_probe_grant_is_exact(self) -> None:
        self.assertEqual(self.policy["grants"].count(self.NEO_O11Y_PROBE_GRANT), 1)
        self.assertIn("tinyland-neo", self.policy["hosts"])
        self.assertEqual(
            [
                grant for grant in self.policy["grants"]
                if "tinyland-neo" in grant["src"] and "tag:mcp-proxy" in grant["dst"]
            ],
            [self.NEO_O11Y_PROBE_GRANT],
        )

    def test_observability_read_and_loki_writer_grants_are_exact(self) -> None:
        self.assertEqual(self.policy["grants"].count(self.OBSERVABILITY_READ_GRANT), 1)
        self.assertEqual(self.policy["grants"].count(self.LOKI_WRITER_GRANT), 1)
        for alias in ("tinyland-honey", "tinyland-bumble", "tinyland-sting"):
            self.assertIn(alias, self.policy["hosts"])

    def test_nothing_else_reaches_mcp_proxy(self) -> None:
        tag = "tag:mcp-proxy"
        self.assertEqual(
            [grant for grant in self.policy["grants"] if tag in grant["dst"]],
            self.MCP_PROXY_GRANTS,
        )
        for grant in self.policy["grants"]:
            if tag in grant["dst"]:
                self.assertTrue(grant.get("ip"))
                self.assertNotIn("*", grant["ip"])
                self.assertNotIn("app", grant)
        for rule in self.policy["acls"]:
            for destination in rule["dst"]:
                host = destination.rpartition(":")[0]
                self.assertNotIn(host, {tag, "*"}, rule)
        for rule in self.policy["ssh"]:
            self.assertNotIn(tag, rule["dst"])

    def test_observability_read_acl_adds_no_tag_or_owner(self) -> None:
        self.assertEqual(
            self.policy["tagOwners"]["tag:mcp-proxy"],
            ["tag:k8s-operator", "autogroup:admin", "group:dollhouse-admins"],
        )
        self.assertEqual(
            set(self.policy["tagOwners"]),
            {
                "tag:dollhouse", "tag:services", "tag:k8s", "tag:k8s-operator",
                "tag:mcp-proxy", "tag:k8s-egress-nodeexporter", "tag:tsidp",
                "tag:dev", "tag:staging", "tag:qa", "tag:anon-gateway",
                "tag:exit-node", "tag:switch", "tag:subnet-router",
                "tag:tinyland-lab-common", "tag:tinyland-lab-sunshine",
                "tag:tinyland-lab-moonlight", "tag:tinyland-lab-crush",
                "tag:tinyland-lab-runner", "tag:tinyland-lab-deploy",
                "tag:tinyland-lab-ci-ephemeral", "tag:tinyland-lab-nix-target",
                "tag:rj-gateway", "tag:setec", "tag:ci-agent", "tag:kvm-proxy",
                "tag:tag-authority",
            },
        )
        for row in self.policy["nodeAttrs"]:
            self.assertNotIn("tag:mcp-proxy", row["target"])

    def test_existing_loki_alias_writer_rule_is_kept_for_now(self) -> None:
        # Retired only after the tag-scoped writer grant is confirmed live.
        rule = {
            "action": "accept",
            "src": ["tinyland-honey", "tinyland-bumble", "tinyland-sting"],
            "dst": ["tinyland-loki-observability:3100"],
        }
        self.assertEqual(self.policy["acls"].count(rule), 1)

    # TIN-4686 Phase 0: Tailscale Services for stable o11y names. The
    # operator ProxyGroup carries tag:mcp-proxy (no new tag) and advertises
    # the six svc:o11y-* Services; autoApprovers.services names each Service
    # exactly. Grants below are the only rules that name any svc:o11y-*.
    O11Y_SERVICES = (
        "svc:o11y-loki", "svc:o11y-tempo", "svc:o11y-mimir",
        "svc:o11y-pyroscope", "svc:o11y-otlp", "svc:o11y-grafana",
    )
    O11Y_READERS = ["group:dollhouse-admins", "tag:mcp-proxy"]
    O11Y_SERVICE_GRANTS = [
        {"src": O11Y_READERS, "dst": ["svc:o11y-loki"], "ip": ["tcp:3100"]},
        {"src": O11Y_READERS, "dst": ["svc:o11y-tempo"], "ip": ["tcp:3200"]},
        {"src": O11Y_READERS, "dst": ["svc:o11y-mimir"], "ip": ["tcp:9009"]},
        {"src": O11Y_READERS, "dst": ["svc:o11y-pyroscope"], "ip": ["tcp:4040"]},
        {
            "src": ["tinyland-honey", "tinyland-bumble", "tinyland-sting"],
            "dst": ["svc:o11y-loki"],
            "ip": ["tcp:3100"],
        },
        # Same principals that reach the current tag:k8s OTLP proxy on 4318 today.
        {
            "src": [
                "group:dollhouse-admins", "group:dollhouse-users", "tag:k8s",
                "tag:k8s-operator", "tag:dev", "tag:ci-agent",
            ],
            "dst": ["svc:o11y-otlp"],
            "ip": ["tcp:4318"],
        },
        # Same principals that reach tinyland-grafana-observability:3000 today.
        {
            "src": [
                "group:dollhouse-admins", "group:dollhouse-users", "tag:k8s",
                "tag:k8s-operator", "tag:dev", "tag:ci-agent", "tinyland-honey",
            ],
            "dst": ["svc:o11y-grafana"],
            "ip": ["tcp:3000"],
        },
    ]

    def test_o11y_service_grants_are_exact(self) -> None:
        for grant in self.O11Y_SERVICE_GRANTS:
            self.assertEqual(self.policy["grants"].count(grant), 1, grant)

    def test_nothing_else_reaches_o11y_services(self) -> None:
        def names_o11y(values):
            return any(value.startswith("svc:o11y-") for value in values)

        self.assertEqual(
            [grant for grant in self.policy["grants"] if names_o11y(grant["dst"])],
            self.O11Y_SERVICE_GRANTS,
        )
        for grant in self.O11Y_SERVICE_GRANTS:
            self.assertEqual(len(grant["dst"]), 1)
            self.assertIn(grant["dst"][0], self.O11Y_SERVICES)
            self.assertEqual(len(grant["ip"]), 1)
            self.assertTrue(grant["ip"][0].startswith("tcp:"))
            self.assertNotIn("app", grant)
        self.assertFalse(any(names_o11y(grant["src"]) for grant in self.policy["grants"]))
        for rule in self.policy["acls"]:
            self.assertFalse(names_o11y(rule["src"] + rule["dst"]), rule)
        for rule in self.policy["ssh"]:
            self.assertFalse(names_o11y(rule["src"] + rule["dst"]), rule)

    def test_o11y_services_auto_approved_for_mcp_proxy_only(self) -> None:
        approvers = self.policy["autoApprovers"]
        self.assertEqual(
            approvers["services"],
            {service: ["tag:mcp-proxy"] for service in self.O11Y_SERVICES},
        )
        self.assertEqual(
            set(approvers),
            {"routes", "exitNode", "services"},
        )
        self.assertNotIn("tag:mcp-proxy", approvers["exitNode"])
        self.assertFalse(any("tag:mcp-proxy" in tags for tags in approvers["routes"].values()))

    def test_o11y_services_change_leaves_tag_mcp_proxy_grants_untouched(self) -> None:
        # The tailnet-acl#29 grants and honey's tcp:8080 grant are unchanged;
        # with the TIN-4686 neo probe they are the only grants whose
        # destination is tag:mcp-proxy.
        self.assertEqual(
            [grant for grant in self.policy["grants"] if "tag:mcp-proxy" in grant["dst"]],
            self.MCP_PROXY_GRANTS,
        )

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
