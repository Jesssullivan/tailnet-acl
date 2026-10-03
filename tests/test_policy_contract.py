import ipaddress
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

    # gftb-probe (operator rulings 2026-10-03; lab design
    # docs/operations/TAILNET_MEMBERSHIP_DETECTION_DESIGN_2026-10-03.md, 3.5):
    # the public greatfallstoolbus.org bundle image-probes this node to learn
    # "is this browser in the GFTB QA group". Ruling, verbatim: "this is the
    # intent; I can add users to the qa tag as needed." So the yes set is one
    # group, group:gftb-qa, and the node stays inbound-only on tcp:443 with no
    # Funnel. (A Funnelled probe would still answer no, since Funnel requests
    # carry no user login; Funnel would make the node internet-reachable.)
    PROBE = "tag:gftb-probe"
    PROBE_CAP = "greatfallstoolbus.org/cap/gftb-probe"
    QA = "group:gftb-qa"

    def test_gftb_qa_group_starts_with_the_operator_only(self) -> None:
        self.assertEqual(
            self.policy["groups"][self.QA], ["jsullivan2@gmail.com", "jess@sulliwood.org"]
        )

    def test_gftb_probe_is_inbound_only_on_443_for_the_qa_group(self) -> None:
        tag = self.PROBE
        mentions = [
            row for row in self.policy["acls"] + self.policy["grants"]
            if any(tag in entry for entry in row["src"] + row["dst"])
        ]
        self.assertEqual(
            mentions,
            [{
                "src": [self.QA],
                "dst": [tag],
                "ip": ["tcp:443"],
                "app": {self.PROBE_CAP: [{"gftb_qa": True}]},
            }],
        )
        # The probe capability is granted nowhere else.
        holders = [row for row in self.policy["grants"] if self.PROBE_CAP in row.get("app", {})]
        self.assertEqual(holders, mentions)
        self.assertFalse(any(tag in row["target"] for row in self.policy["nodeAttrs"]))
        self.assertFalse(any(tag in row["src"] or tag in row["dst"] for row in self.policy["ssh"]))
        self.assertNotIn(tag, self.policy["autoApprovers"]["exitNode"])
        self.assertFalse(any(tag in tags for tags in self.policy["autoApprovers"]["routes"].values()))

    def test_gftb_probe_owners_and_no_second_tag(self) -> None:
        """A tag:gftb-probe node must never also carry a Funnel or broad tag.

        Policy cannot forbid a device from holding two tags. It can make that
        hard: (1) only autogroup:admin owns tag:gftb-probe, so no non-admin
        user and no tagged device (tag:tag-authority included) can mint it,
        alone or next to another tag; (2) tag:gftb-probe owns no tag, so the
        probe node itself cannot advertise a second one; (3) the tag is never
        a Funnel target, a source, an SSH party or an auto-approver. An admin
        could still add a tag by hand in the console; the host-side guard in
        xoxd-ai/lab (backend.py node_state, serve.sh) refuses to answer yes
        and resets serve unless Self.Tags is exactly ["tag:gftb-probe"].
        """
        tag = self.PROBE
        owners = self.policy["tagOwners"]
        self.assertEqual(owners[tag], ["autogroup:admin"])
        self.assertFalse(
            [other for other, who in owners.items() if tag in who],
            "tag:gftb-probe must own no tag, or the probe node could advertise it",
        )
        funnel = {t for row in self.policy["nodeAttrs"] if "funnel" in row["attr"] for t in row["target"]}
        sources = {
            s for row in self.policy["acls"] + self.policy["grants"] for s in row["src"] if s.startswith("tag:")
        }
        ssh_parties = {
            p for row in self.policy["ssh"] for p in row["src"] + row["dst"] if p.startswith("tag:")
        }
        risky = funnel | sources | ssh_parties
        self.assertIn("tag:dollhouse", risky)
        self.assertNotIn(tag, risky)
        for other in sorted(risky):
            self.assertNotIn(tag, owners.get(other, []), other)

    def test_nothing_wider_than_the_one_grant_reaches_gftb_probe(self) -> None:
        tag = self.PROBE
        universal = {"*", "autogroup:tagged", "0.0.0.0/0", "::/0", "100.64.0.0/10"}
        for row in self.policy["acls"]:
            self.assertFalse(universal.intersection(dst.rsplit(":", 1)[0] for dst in row["dst"]))
        for row in self.policy["grants"]:
            self.assertFalse(universal.intersection(row["dst"]))
        # A narrower CGNAT CIDR or a hosts alias could still reach the probe
        # node's address. Every tailnet-range destination must be exactly one
        # named host address from the hosts map.
        hosts = self.policy["hosts"]
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        named = set()
        for name, value in hosts.items():
            net = ipaddress.ip_network(value, strict=False)
            if net.version == 4 and net.overlaps(cgnat):
                self.assertEqual(net.prefixlen, 32, name)
                named.add(net)
        dsts = [dst.rsplit(":", 1)[0] for row in self.policy["acls"] for dst in row["dst"]]
        dsts += [dst for row in self.policy["grants"] for dst in row["dst"]]
        for dst in dsts:
            target = hosts.get(dst, dst)
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                continue  # a tag, group, autogroup or service name
            if net.version == 4 and net.overlaps(cgnat):
                self.assertIn(net, named, dst)
        self.assertNotIn(tag, hosts)

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
    # TIN-4686 Phase 2: petting-zoo-mini's Darwin Loki shipper joins the
    # writers (lab#1945). Tailscale has no write-only port: tcp:3100 is also
    # Loki's read API, so every writer here can read raw logs too.
    LOKI_WRITERS = [
        "tinyland-honey", "tinyland-bumble", "tinyland-sting",
        "tinyland-petting-zoo-mini",
    ]
    LOKI_WRITER_GRANT = {
        "src": LOKI_WRITERS,
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:3100"],
    }
    HONEY_MCP_GRANT = {
        "src": ["tinyland-honey"],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:8080"],
    }
    # TIN-4686: a client only receives the o11y Service host peer (and so
    # reaches the VIP) when it also holds a device-level grant to the hosts'
    # tag, tag:mcp-proxy, on the service port. The neo probe proved it. Every
    # svc:o11y-* grant therefore has a device "twin" to tag:mcp-proxy with
    # the same sources and ports. Loki/Tempo readers and Loki writers are
    # twinned by the tailnet-acl#29 grants above; these four twin the rest.
    MIMIR_DEVICE_TWIN = {
        "src": ["group:dollhouse-admins", "tag:mcp-proxy"],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:9009"],
    }
    PYROSCOPE_DEVICE_TWIN = {
        "src": ["group:dollhouse-admins", "tag:mcp-proxy"],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:4040"],
    }
    OTLP_DEVICE_TWIN = {
        "src": [
            "group:dollhouse-admins", "group:dollhouse-users", "tag:k8s",
            "tag:k8s-operator", "tag:dev", "tag:ci-agent",
        ],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:4318"],
    }
    GRAFANA_DEVICE_TWIN = {
        "src": [
            "group:dollhouse-admins", "group:dollhouse-users", "tag:k8s",
            "tag:k8s-operator", "tag:dev", "tag:ci-agent", "tinyland-honey",
        ],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:3000"],
    }
    # Retired: the neo probe, now covered by the OTLP and Grafana twins via
    # neo's tags (tag:k8s, tag:k8s-operator, tag:dev).
    NEO_O11Y_PROBE_GRANT = {
        "src": ["tinyland-neo"],
        "dst": ["tag:mcp-proxy"],
        "ip": ["tcp:3000", "tcp:4318"],
    }
    MCP_PROXY_GRANTS = [
        HONEY_MCP_GRANT,
        OBSERVABILITY_READ_GRANT,
        LOKI_WRITER_GRANT,
        MIMIR_DEVICE_TWIN,
        PYROSCOPE_DEVICE_TWIN,
        OTLP_DEVICE_TWIN,
        GRAFANA_DEVICE_TWIN,
    ]

    def test_o11y_device_twin_grants_are_exact(self) -> None:
        for grant in (
            self.MIMIR_DEVICE_TWIN, self.PYROSCOPE_DEVICE_TWIN,
            self.OTLP_DEVICE_TWIN, self.GRAFANA_DEVICE_TWIN,
        ):
            self.assertEqual(self.policy["grants"].count(grant), 1, grant)

    def test_neo_o11y_probe_grant_is_retired(self) -> None:
        self.assertNotIn(self.NEO_O11Y_PROBE_GRANT, self.policy["grants"])
        self.assertFalse(any(
            "tinyland-neo" in grant["src"] and "tag:mcp-proxy" in grant["dst"]
            for grant in self.policy["grants"]
        ))
        # neo's tags are device state, not policy; the twins cover them.
        for tag in ("tag:k8s", "tag:k8s-operator", "tag:dev"):
            self.assertIn(tag, self.OTLP_DEVICE_TWIN["src"])
            self.assertIn(tag, self.GRAFANA_DEVICE_TWIN["src"])

    def test_every_o11y_service_grant_has_a_device_twin(self) -> None:
        # For each grant naming a svc:o11y-* destination, some single grant
        # to exactly tag:mcp-proxy covers a superset of its sources and ports.
        service_grants = [
            grant for grant in self.policy["grants"]
            if any(dst.startswith("svc:o11y-") for dst in grant["dst"])
        ]
        self.assertEqual(len(service_grants), 7)
        device_grants = [
            grant for grant in self.policy["grants"]
            if grant["dst"] == ["tag:mcp-proxy"]
        ]
        for service_grant in service_grants:
            self.assertTrue(
                any(
                    set(service_grant["src"]) <= set(twin["src"])
                    and set(service_grant["ip"]) <= set(twin.get("ip", []))
                    for twin in device_grants
                ),
                service_grant,
            )

    def test_observability_read_and_loki_writer_grants_are_exact(self) -> None:
        self.assertEqual(self.policy["grants"].count(self.OBSERVABILITY_READ_GRANT), 1)
        self.assertEqual(self.policy["grants"].count(self.LOKI_WRITER_GRANT), 1)
        for alias in self.LOKI_WRITERS:
            self.assertIn(alias, self.policy["hosts"])

    def test_petting_zoo_mini_is_only_a_loki_writer_and_metrics_target(self) -> None:
        alias = "tinyland-petting-zoo-mini"
        loki_writer_service_grant = {
            "src": self.LOKI_WRITERS, "dst": ["svc:o11y-loki"], "ip": ["tcp:3100"],
        }
        self.assertEqual(
            [grant for grant in self.policy["grants"] if alias in grant["src"]],
            [self.LOKI_WRITER_GRANT, loki_writer_service_grant],
        )
        self.assertEqual(
            [grant for grant in self.policy["grants"] if alias in grant["dst"]],
            [{
                "src": ["tag:k8s-egress-nodeexporter"],
                "dst": ["tinyland-relay-1", alias, "tinyland-neo"],
                "ip": ["tcp:9100"],
            }],
        )
        # The retiring alias-scoped ACL writer rule is not widened.
        for rule in self.policy["acls"]:
            self.assertNotIn(alias, rule["src"], rule)

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
                "tag:gftb-probe", "tag:dev", "tag:staging", "tag:qa", "tag:anon-gateway",
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
        {"src": LOKI_WRITERS, "dst": ["svc:o11y-loki"], "ip": ["tcp:3100"]},
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
        # with the TIN-4686 device twins they are the only grants whose
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


    # Operator rulings 2026-10-03 ("all the buttons / membership / join button
    # in header etc should conditionally show only on tailnet and/or CF access
    # logged in; feature flag style." and "lets design and implement both in
    # ultracode"): tsidp as a Cloudflare Access IdP for the GFTB members gate
    # (xoxd-ai/lab TAILNET_MEMBERSHIP_DETECTION_DESIGN_2026-10-03.md 4.3).
    TSIDP_GRANTS = [
        {
            "src": ["group:dollhouse-admins"],
            "dst": ["tag:tsidp"],
            "app": {"tailscale.com/cap/tsidp": [{"allow_admin_ui": True}]},
        },
        {
            "src": ["group:gftb-members"],
            "dst": ["tag:tsidp"],
            "app": {"tailscale.com/cap/tsidp": [{
                "users": ["*"],
                "resources": ["*"],
                "extraClaims": {"gftb_member": True},
                "includeInUserInfo": True,
            }]},
        },
        {
            "src": ["group:gftb-members", "group:dollhouse-admins"],
            "dst": ["tag:tsidp"],
            "ip": ["tcp:443"],
        },
    ]

    def test_tsidp_grants_are_exact_and_current_schema(self) -> None:
        self.assertEqual(
            [grant for grant in self.policy["grants"] if "tag:tsidp" in grant["src"] + grant["dst"]],
            self.TSIDP_GRANTS,
        )

    def test_tsidp_capability_never_grants_dcr_and_admin_ui_only_to_admins(self) -> None:
        for grant in self.policy["grants"]:
            for rules in grant.get("app", {}).values():
                for rule in rules:
                    self.assertNotIn("allow_dcr", rule)
                    self.assertNotIn("admin", rule)
                    if rule.get("allow_admin_ui"):
                        self.assertEqual(grant["src"], ["group:dollhouse-admins"])
                    if "extraClaims" in rule:
                        self.assertEqual(grant["src"], ["group:gftb-members"])

    def test_tsidp_has_no_outbound_access_and_only_tcp_443_inbound(self) -> None:
        tag = "tag:tsidp"
        for rule in self.policy["acls"]:
            self.assertNotIn(tag, rule["src"])
        for rule in self.policy["grants"]:
            self.assertNotIn(tag, rule["src"])
        for rule in self.policy["ssh"]:
            self.assertNotIn(tag, rule["src"])
            self.assertNotIn(tag, rule["dst"])
        reach = [rule for rule in self.policy["acls"] if any(dst.rpartition(":")[0] == tag for dst in rule["dst"])]
        self.assertTrue(all("tag:k8s" not in rule["src"] for rule in reach))
        self.assertTrue(all(rule["src"] == ["tag:dev"] for rule in reach), reach)

    def test_funnel_only_for_dollhouse_and_tsidp(self) -> None:
        funnel = [row for row in self.policy["nodeAttrs"] if "funnel" in row["attr"]]
        self.assertEqual(
            funnel,
            [
                {"target": ["tag:dollhouse"], "attr": ["funnel"]},
                {"target": ["tag:tsidp"], "attr": ["funnel"]},
            ],
        )

    def test_gftb_members_group_starts_with_the_operator(self) -> None:
        self.assertEqual(
            self.policy["groups"]["group:gftb-members"],
            ["jsullivan2@gmail.com", "jess@sulliwood.org"],
        )
        self.assertEqual(
            self.policy["tagOwners"]["tag:tsidp"],
            ["tag:tag-authority", "autogroup:admin", "group:dollhouse-admins"],
        )

if __name__ == "__main__":
    unittest.main()
