import ipaddress
import json
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

    # RemoteJuggler teardown (TIN-6890, SSOT ruling J70, Jess 2026-10-22).
    # rj-gateway and setec are retired: no tag, rule, grant or capability may
    # name them, and nothing may hold the tailscale.com/cap/secrets grant they
    # used. tag:ci-agent stays (the Aperture ai:* row and observability grants
    # still list it), but its RemoteJuggler-era reach is gone: no dev/k8s reach
    # and no autogroup:internet egress.
    RJ_TAGS = ("tag:rj-gateway", "tag:setec")

    def test_remotejuggler_tags_are_gone(self) -> None:
        for tag in self.RJ_TAGS:
            self.assertNotIn(tag, self.policy["tagOwners"])
            self.assertNotIn(tag, json.dumps(self.policy))

    def test_remotejuggler_caps_are_gone(self) -> None:
        for row in self.policy["grants"]:
            app = row.get("app", {})
            self.assertNotIn("tinyland.dev/cap/rj-gateway", app)
            self.assertNotIn("tailscale.com/cap/secrets", app)

    def test_ci_agent_has_no_acl_reach_or_internet_egress(self) -> None:
        tag = "tag:ci-agent"
        self.assertEqual(
            self.policy["tagOwners"][tag], ["autogroup:admin", "group:dollhouse-admins"]
        )
        for row in self.policy["acls"]:
            if tag in row["src"]:
                self.assertEqual(row["dst"], ["ai:*"])
        for row in self.policy["grants"]:
            if tag in row["src"]:
                self.assertNotIn("autogroup:internet", row["dst"])
                self.assertNotIn("app", row)

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

    NEO = "tinyland-neo"
    NEO_LOGIN = "jess@sulliwood.org"

    def test_gftb_probe_is_inbound_only_on_443_for_the_qa_group_and_neo(self) -> None:
        # Operator ruling 2026-10-05 (TIN-5371): the primary identity machine
        # carries the QA identity in policy, as a capability parameter, because
        # a tagged device has no user for Serve to forward.
        tag = self.PROBE
        mentions = [
            row for row in self.policy["acls"] + self.policy["grants"]
            if any(tag in entry for entry in row["src"] + row["dst"])
        ]
        self.assertEqual(
            mentions,
            [
                {
                    "src": [self.QA],
                    "dst": [tag],
                    "ip": ["tcp:443"],
                    "app": {self.PROBE_CAP: [{"gftb_qa": True}]},
                },
                {
                    "src": [self.NEO],
                    "dst": [tag],
                    "ip": ["tcp:443"],
                    "app": {self.PROBE_CAP: [{"gftb_qa": True, "user": self.NEO_LOGIN}]},
                },
            ],
        )
        # The probe capability has exactly two holders: the group and neo.
        holders = [row for row in self.policy["grants"] if self.PROBE_CAP in row.get("app", {})]
        self.assertEqual(holders, mentions)
        self.assertEqual(self.policy["hosts"][self.NEO], "100.67.93.34")
        params = holders[1]["app"][self.PROBE_CAP]
        self.assertEqual(len(params), 1)
        self.assertIsInstance(params[0]["user"], str)
        self.assertEqual(len(params[0]["user"].split()), 1)
        self.assertEqual(self.policy["groups"][self.QA].count(params[0]["user"]), 1)
        self.assertNotIn("tag:qa", [s for row in holders for s in row["src"]])
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

    def test_honey_and_bumble_mcp_access_is_tcp_only_and_tag_scoped(self) -> None:
        # Operator ruling 2026-10-28 (TIN-4655): bumble joins honey on the
        # switchboard broker proxy, tag:mcp-proxy tcp:8080. bumble carries
        # tag:dollhouse only, so it is named by alias. sting is not added.
        self.assertEqual(self.policy["grants"].count(self.MCP_PROXY_8080_GRANT), 1)
        self.assertNotIn("tinyland-sting", self.MCP_PROXY_8080_GRANT["src"])

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

    def test_dollhouse_reaches_k8s_https_443_only_for_loki_push_r_w52(self) -> None:
        # R-W52 (TIN-5694, TIN-5150, blahaj #2088): tag:dollhouse nodes (honey)
        # reach HTTPS services on tag:k8s, e.g. loki-push.taila4c78d.ts.net.
        rule = {"action": "accept", "src": ["tag:dollhouse"], "dst": ["tag:k8s:443"]}
        self.assertEqual(self.policy["acls"].count(rule), 1)

    # R-C1011 (TIN-5770 comment 86411716; exploration blahaj #2328): the
    # public MX relay-1 moves alone from tag:dollhouse to tag:mx-relay, which
    # leaves the dollhouse mesh (tag:dollhouse:*, every voter port) and the
    # dollhouse root Tailscale SSH rule. The change is additive: these five
    # grants are the tag's only rules and tag:dollhouse is unchanged. The
    # loki-push row supersedes tailnet-acl#55 (R-C964).
    MX_RELAY = "tag:mx-relay"
    RELAY_ALIAS = "tinyland-relay-1"
    RELAY_IP = "100.102.229.122"
    MX_RELAY_GRANTS = [
        {"src": ["tinyland-honey"], "dst": ["tag:mx-relay"],
         "ip": ["tcp:22", "tcp:25", "tcp:9100", "tcp:9154"]},
        {"src": ["tinyland-neo"], "dst": ["tag:mx-relay"], "ip": ["tcp:22"]},
        {"src": ["group:dollhouse-admins"], "dst": ["tag:mx-relay"], "ip": ["tcp:22"]},
        {"src": ["tag:mx-relay"], "dst": ["tinyland-honey"], "ip": ["tcp:25", "tcp:465"]},
        {"src": ["tag:mx-relay"], "dst": ["tinyland-loki-push"], "ip": ["tcp:443"]},
    ]
    EXPORTER_EGRESS_GRANT = {
        "src": ["tag:k8s-egress-nodeexporter"],
        "dst": ["tinyland-relay-1", "tinyland-petting-zoo-mini", "tinyland-neo"],
        "ip": ["tcp:9100"],
    }
    MX_RELAY_POLICY_TEST = {
        "src": "tag:mx-relay",
        "proto": "tcp",
        "accept": ["tinyland-honey:25", "tinyland-honey:465", "tinyland-loki-push:443"],
        "deny": [
            "tinyland-honey:22", "tinyland-honey:80", "tinyland-honey:443",
            "tinyland-honey:587", "tinyland-honey:2379", "tinyland-honey:6443",
            "tinyland-honey:9100", "tinyland-honey:9345", "tinyland-honey:10250",
            "tinyland-bumble:22", "tinyland-bumble:25", "tinyland-bumble:443",
            "tinyland-bumble:465", "tinyland-bumble:6443", "tinyland-bumble:9345",
            "tinyland-bumble:10250",
            "tinyland-sting:22", "tinyland-sting:25", "tinyland-sting:443",
            "tinyland-sting:465", "tinyland-sting:6443", "tinyland-sting:9345",
            "tinyland-sting:10250",
            "tinyland-neo:22", "tinyland-petting-zoo-mini:22",
            "tinyland-loki-push:3100", "tinyland-loki-observability:3100",
            "tag:dollhouse:22", "tag:dollhouse:6443",
            # The wider reach the retag removes. No tag:k8s:443 deny:
            # loki-push is tag:k8s and granted on 443, so named tag:k8s hosts
            # stand in for it.
            "tag:k8s:6443", "tag:k8s-operator:443",
            "tinyland-mcp-arxiv:443", "tinyland-neo:443",
            "ai:443", "192.168.30.105:22",
        ],
    }
    HONEY_TO_RELAY_POLICY_TEST = {
        "src": "tinyland-honey",
        "proto": "tcp",
        "accept": [
            "tinyland-relay-1:22", "tinyland-relay-1:25",
            "tinyland-relay-1:9100", "tinyland-relay-1:9154",
        ],
        "deny": ["tinyland-loki-push:3100"],
    }
    # The operator :22 paths, before the retag (dollhouse mesh) and after it
    # (the neo and group:dollhouse-admins rows). A user source is an untagged
    # device of that user, which is the break-glass path.
    NEO_TO_RELAY_POLICY_TEST = {
        "src": "tinyland-neo",
        "proto": "tcp",
        "accept": ["tinyland-relay-1:22"],
        "deny": ["tinyland-loki-observability:22"],
    }
    ADMIN_USER_TO_RELAY_POLICY_TEST = {
        "src": "jess@sulliwood.org",
        "proto": "tcp",
        "accept": ["tinyland-relay-1:22"],
        "deny": ["tinyland-loki-observability:22"],
    }
    # Kept on purpose, outside R-C1011's list (flagged for the operator): the
    # observability node-exporter scrape through the egress proxy.
    EXPORTER_EGRESS_POLICY_TEST = {
        "src": "tag:k8s-egress-nodeexporter",
        "proto": "tcp",
        "accept": ["tinyland-relay-1:9100"],
        "deny": ["tinyland-relay-1:22", "tinyland-relay-1:25", "tinyland-relay-1:9154"],
    }

    def _names_relay(self, entry: str) -> bool:
        """True when a src or dst entry (no port) covers relay-1 once retagged."""
        if entry in {
            self.MX_RELAY, self.RELAY_ALIAS, "*", "autogroup:tagged", "autogroup:danger-all",
        }:
            return True
        target = self.policy["hosts"].get(entry, entry)
        try:
            return ipaddress.ip_address(self.RELAY_IP) in ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False  # another tag, group, autogroup, user or service

    def test_mx_relay_is_owned_by_admins_only_and_owns_no_tag(self) -> None:
        owners = self.policy["tagOwners"]
        self.assertEqual(owners[self.MX_RELAY], ["autogroup:admin", "group:dollhouse-admins"])
        self.assertNotIn("tag:tag-authority", owners[self.MX_RELAY])
        self.assertFalse(
            [tag for tag, who in owners.items() if self.MX_RELAY in who],
            "tag:mx-relay must own no tag, or the relay could advertise a second one",
        )
        # tag:dollhouse itself is unchanged: same owners, same mesh, same SSH.
        self.assertEqual(
            owners["tag:dollhouse"],
            ["tag:tag-authority", "autogroup:admin", "group:dollhouse-admins"],
        )
        mesh = {"action": "accept", "src": ["tag:dollhouse"], "dst": ["tag:dollhouse:*"]}
        self.assertEqual(self.policy["acls"].count(mesh), 1)

    def test_mx_relay_rules_are_exactly_the_five_ruled_grants(self) -> None:
        tag = self.MX_RELAY
        self.assertEqual(
            [row for row in self.policy["grants"] if tag in row["src"] + row["dst"]],
            self.MX_RELAY_GRANTS,
        )
        for row in self.policy["acls"]:
            self.assertFalse(
                any(e == tag or e.startswith(tag + ":") for e in row["src"] + row["dst"]), row
            )
        hosts = self.policy["hosts"]
        self.assertEqual(hosts[self.RELAY_ALIAS], self.RELAY_IP)
        self.assertEqual(hosts["tinyland-honey"], "100.113.89.12")
        self.assertEqual(hosts["tinyland-neo"], "100.67.93.34")
        self.assertEqual(hosts["tinyland-loki-push"], "100.85.50.69")
        # The loki-push alias is reached only by the relay shipper row.
        self.assertEqual(
            [row for row in self.policy["grants"] if "tinyland-loki-push" in row["dst"]],
            [self.MX_RELAY_GRANTS[4]],
        )
        for row in self.policy["acls"]:
            self.assertFalse(any(d.startswith("tinyland-loki-push:") for d in row["dst"]), row)

    def test_mx_relay_reaches_only_honey_25_465_and_loki_push_443(self) -> None:
        # Every rule that would apply to relay-1 as a source after the retag:
        # its tag, its alias, an address range holding it, or a universal
        # source. Policy is additive, so this set is its whole reach.
        reach = set()
        for row in self.policy["acls"]:
            if any(self._names_relay(src) for src in row["src"]):
                reach.update(("acl", d) for d in row["dst"])
        for row in self.policy["grants"]:
            if any(self._names_relay(src) for src in row["src"]):
                self.assertNotIn("app", row)
                reach.update((d, ip) for d in row["dst"] for ip in row.get("ip", ["*"]))
        self.assertEqual(
            reach,
            {
                ("tinyland-honey", "tcp:25"),
                ("tinyland-honey", "tcp:465"),
                ("tinyland-loki-push", "tcp:443"),
            },
        )
        # So no other honey port (22, 6443, 9345, 10250, ...), and nothing on
        # bumble or sting by alias, address or a tag they carry.
        voters = {
            "tinyland-bumble", "tinyland-sting", "100.88.101.107", "100.85.46.118",
            "tag:dollhouse", "tag:k8s",
        }
        self.assertFalse({host for host, _ in reach} & voters)

    def test_mx_relay_has_no_ssh_rule_node_attr_or_auto_approver(self) -> None:
        for rule in self.policy["ssh"]:
            for party in rule["src"] + rule["dst"]:
                self.assertFalse(self._names_relay(party), rule)
        for row in self.policy["nodeAttrs"]:
            self.assertFalse(any(self._names_relay(t) for t in row["target"]), row)
        approvers = self.policy["autoApprovers"]
        self.assertNotIn(self.MX_RELAY, approvers["exitNode"])
        for section in ("routes", "services"):
            for owners in approvers.get(section, {}).values():
                self.assertNotIn(self.MX_RELAY, owners)

    def test_relay_inbound_is_exact_and_only_honey_reaches_smtp(self) -> None:
        # After the retag, these are the only rules with relay-1 as a
        # destination. Tailnet SMTP probes from neo, sting and bumble to
        # relay:25 are retired (R-C1011); honey is the one tailnet SMTP client.
        self.assertEqual(
            [row for row in self.policy["grants"] if any(self._names_relay(d) for d in row["dst"])],
            [self.EXPORTER_EGRESS_GRANT] + self.MX_RELAY_GRANTS[:3],
        )
        for row in self.policy["acls"]:
            self.assertFalse(
                any(self._names_relay(d.rpartition(":")[0]) for d in row["dst"]), row
            )
        smtp_sources = {
            src
            for row in self.policy["grants"]
            if any(self._names_relay(d) for d in row["dst"])
            and {"tcp:25", "*"} & set(row.get("ip", ["*"]))
            for src in row["src"]
        }
        self.assertEqual(smtp_sources, {"tinyland-honey"})

    def test_exporter_egress_scrape_of_relay_is_an_intentional_keep(self) -> None:
        # Outside R-C1011's enumerated list, kept on purpose: the existing
        # observability Prometheus node-exporter scrape (TIN-4324). It keys on
        # the relay alias, survives the retag unchanged, and is the only
        # non-R-C1011 row that reaches the relay. Port 9100 only.
        rows = [
            row for row in self.policy["grants"]
            if any(self._names_relay(d) for d in row["dst"]) and self.MX_RELAY not in row["dst"]
        ]
        self.assertEqual(rows, [self.EXPORTER_EGRESS_GRANT])
        self.assertEqual(self.EXPORTER_EGRESS_GRANT["ip"], ["tcp:9100"])
        self.assertNotIn("app", self.EXPORTER_EGRESS_GRANT)
        self.assertIn(self.EXPORTER_EGRESS_POLICY_TEST, self.policy["tests"])

    def test_break_glass_is_the_dollhouse_admins_row_for_untagged_devices(self) -> None:
        # R-C1011 names dollhouse-admins and untagged break-glass separately;
        # a group source matches only its members' untagged devices, so one
        # row is both. Its members are exactly the operator's two identities.
        self.assertIn(self.MX_RELAY_GRANTS[2], self.policy["grants"])
        self.assertEqual(self.MX_RELAY_GRANTS[2]["src"], ["group:dollhouse-admins"])
        self.assertEqual(
            self.policy["groups"]["group:dollhouse-admins"],
            ["jsullivan2@gmail.com", "jess@sulliwood.org"],
        )
        self.assertIn(self.ADMIN_USER_TO_RELAY_POLICY_TEST, self.policy["tests"])
        self.assertIn(self.NEO_TO_RELAY_POLICY_TEST, self.policy["tests"])

    # R-C1011 closeout step 3 (R-C1033; T0 2026-10-21T05:52:46Z, receipt
    # TIN-5770 8c460876). Tests that name the relay by its alias, which
    # Tailscale resolves against the live device. They pass only while relay-1
    # is tag:mx-relay alone, so every validate re-reads the retag server-side.
    POST_RETAG_RATCHET_TESTS = [
        {
            "src": "tinyland-relay-1",
            "proto": "tcp",
            "accept": ["tinyland-honey:25", "tinyland-honey:465"],
            "deny": [
                "tinyland-honey:22", "tinyland-honey:6443", "tinyland-honey:9345",
                "tinyland-honey:10250",
                "tinyland-bumble:22", "tinyland-bumble:6443", "tinyland-bumble:10250",
                "tinyland-sting:22", "tinyland-sting:6443", "tinyland-sting:10250",
            ],
        },
        {
            "src": "tinyland-neo",
            "proto": "tcp",
            "accept": ["tinyland-relay-1:22"],
            "deny": ["tinyland-relay-1:25"],
        },
        {
            "src": "tinyland-sting",
            "proto": "tcp",
            "accept": ["tinyland-loki-observability:3100"],
            "deny": ["tinyland-relay-1:25", "tinyland-relay-1:22"],
        },
        {
            "src": "tinyland-bumble",
            "proto": "tcp",
            "accept": ["tinyland-loki-observability:3100"],
            "deny": ["tinyland-relay-1:25", "tinyland-relay-1:22"],
        },
    ]
    RELAY_ALIAS_SSH_RATCHET = {
        "src": "tinyland-relay-1",
        "dst": ["tinyland-honey", "tinyland-bumble", "tinyland-sting"],
        "deny": ["root"],
    }

    def test_post_retag_ratchet_names_the_relay_by_alias(self) -> None:
        # The ratchet must key on the relay's alias, the live device, and not
        # on the tag; a tag-sourced test would pass whatever the relay's tags.
        for entry in self.POST_RETAG_RATCHET_TESTS:
            self.assertIn(entry, self.policy["tests"])
        self.assertEqual(self.policy["hosts"][self.RELAY_ALIAS], self.RELAY_IP)
        relay_src = [t for t in self.policy["tests"] if t["src"] == self.RELAY_ALIAS]
        self.assertEqual(relay_src, [self.POST_RETAG_RATCHET_TESTS[0]])
        # The tailnet SMTP probe retirement: no neo, sting or bumble source
        # reaches relay-1:25 in policy, and every one is denied it in a test.
        for src in ("tinyland-neo", "tinyland-sting", "tinyland-bumble"):
            denies = [d for t in self.policy["tests"] if t["src"] == src for d in t["deny"]]
            self.assertIn("tinyland-relay-1:25", denies, src)
        self.assertIn(self.RELAY_ALIAS_SSH_RATCHET, self.policy["sshTests"])

    def test_ssh_tests_pin_that_mx_relay_has_no_tailscale_ssh(self) -> None:
        # Tailscale runs sshTests on every validate and write, so a rule that
        # gave tag:mx-relay SSH as any of these users would be refused
        # server-side, not only here.
        self.assertEqual(
            self.policy["sshTests"],
            [{
                "src": self.MX_RELAY,
                "dst": [
                    "tinyland-honey", "tinyland-bumble", "tinyland-sting",
                    "tinyland-petting-zoo-mini", "tag:dollhouse", "tag:dev", "tag:switch",
                ],
                "deny": ["root", "jess", "jsullivan2", "admin"],
            }, self.RELAY_ALIAS_SSH_RATCHET],
        )
        for entry in self.policy["sshTests"]:
            self.assertTrue(all(entry[key] for key in entry), entry)
        hosts = self.policy["hosts"]
        for name in ("tinyland-honey", "tinyland-bumble", "tinyland-sting", "tinyland-petting-zoo-mini"):
            self.assertIn(name, hosts)

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
    # Operator ruling 2026-10-28 (TIN-4655): honey and bumble reach the
    # switchboard broker proxy (agents.xoxd.ai, mcp-agents) on tcp:8080.
    MCP_PROXY_8080_GRANT = {
        "src": ["tinyland-honey", "tinyland-bumble"],
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
        MCP_PROXY_8080_GRANT,
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
        # R-GOLIVE-20261020-c (TIN-6787) adds one source row: petting-zoo-mini
        # is an agent seat and reaches the printstack Ingress proxies on
        # tcp:443 only.
        printstack_seat_grant = {
            "src": ["group:dollhouse-admins"] + self.PRINTSTACK_SEATS,
            "dst": [self.PRINTSTACK],
            "ip": ["tcp:443"],
        }
        self.assertEqual(
            [grant for grant in self.policy["grants"] if alias in grant["src"]],
            [self.LOKI_WRITER_GRANT, loki_writer_service_grant, printstack_seat_grant],
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
                "tag:ci-agent", "tag:kvm-proxy",
                "tag:tag-authority", "tag:gftb-idp", "tag:tofu-state", "tag:infra-idp",
                "tag:interim-build", "tag:honey-relay", "tag:mx-relay",
                "tag:gf-reapi-cell-egress", "tag:gf-reapi-linux-worker",
                "tag:gf-reapi-rocm-worker", "tag:printstack", "tag:softproxy",
            },
        )
        for row in self.policy["nodeAttrs"]:
            self.assertNotIn("tag:mcp-proxy", row["target"])

    def test_interim_build_trial_grants_are_narrow(self) -> None:
        # TIN-5694 R-W5-20261008: DreamCompute trial nodes get operator SSH in
        # and iperf3 out to tag:dollhouse only, until GF leaf/runner stacks land.
        rows = [
            row for row in self.policy["acls"]
            if "tag:interim-build" in row["src"]
            or any(dst.startswith("tag:interim-build:") for dst in row["dst"])
        ]
        self.assertEqual(
            sorted((tuple(r["src"]), tuple(r["dst"])) for r in rows),
            sorted([
                (("jsullivan2@gmail.com", "100.67.93.34"), ("tag:interim-build:22",)),
                (("tag:interim-build",), ("tag:dollhouse:5201",)),
            ]),
        )

    RELAY_CAP = "tailscale.com/cap/relay"

    def test_honey_relay_tag_is_owned_like_dollhouse(self) -> None:
        # TIN-5694 R-W13-20261008: honey is the peer relay for DreamCompute
        # trial nodes; the tag is owned exactly like tag:dollhouse.
        self.assertEqual(
            self.policy["tagOwners"]["tag:honey-relay"],
            self.policy["tagOwners"]["tag:dollhouse"],
        )

    def test_relay_grants_are_exactly_the_dollhouse_mesh_and_interim_to_honey(self) -> None:
        # Peer relay is allocated by the client (src) on the relay server
        # (dst). tag:interim-build may use only tag:honey-relay, and that
        # grant carries the relay cap alone: no ip and no other app cap.
        relay_rows = [
            row for row in self.policy["grants"] if self.RELAY_CAP in row.get("app", {})
        ]
        self.assertEqual(
            sorted((tuple(r["src"]), tuple(r["dst"])) for r in relay_rows),
            sorted([
                (("tag:dollhouse",), ("tag:dollhouse",)),
                (("tag:interim-build",), ("tag:honey-relay",)),
            ]),
        )
        self.assertEqual(
            self.policy["grants"].count(
                {"src": ["tag:interim-build"], "dst": ["tag:honey-relay"], "app": {self.RELAY_CAP: [{}]}}
            ),
            1,
        )

    def test_honey_relay_tag_appears_only_in_the_relay_grant(self) -> None:
        tag = "tag:honey-relay"
        rows = [
            row for row in self.policy["acls"] + self.policy["grants"]
            if tag in row["src"] or any(d == tag or d.startswith(tag + ":") for d in row["dst"])
        ]
        self.assertEqual(
            rows,
            [{"src": ["tag:interim-build"], "dst": [tag], "app": {self.RELAY_CAP: [{}]}}],
        )
        for rule in self.policy["ssh"]:
            self.assertNotIn(tag, rule["src"] + rule["dst"])
        self.assertFalse(any(tag in tags for tags in self.policy["autoApprovers"]["routes"].values()))
        self.assertNotIn(tag, self.policy["autoApprovers"].get("exitNode", []))

    def test_gf_reapi_linux_leaf_route_is_single_port_and_tag_scoped(self) -> None:
        # TIN-5694 R-W5-20261008: the gf-rbe cell's operator egress proxy
        # dials off-prem REAPI WorkerLeaves on 8981 only. Leaf keys are minted
        # per instance by the tag authority, never by the k8s operator.
        self.assertEqual(
            self.policy["tagOwners"]["tag:gf-reapi-cell-egress"],
            ["tag:k8s-operator", "autogroup:admin", "group:dollhouse-admins"],
        )
        self.assertEqual(
            self.policy["tagOwners"]["tag:gf-reapi-linux-worker"],
            ["tag:tag-authority", "autogroup:admin", "group:dollhouse-admins"],
        )
        route_tags = ("tag:gf-reapi-cell-egress", "tag:gf-reapi-linux-worker")
        references = [
            (surface, rule)
            for surface in ("acls", "grants", "ssh")
            for rule in self.policy[surface]
            if any(
                endpoint == tag or endpoint.startswith(f"{tag}:")
                for key in ("src", "dst")
                for endpoint in rule.get(key, [])
                for tag in route_tags
            )
        ]
        # The cell egress tag also fronts the ROCm worker (TIN-5861); that
        # second row is pinned by the rocm-worker test below.
        self.assertEqual(
            references,
            [
                ("grants", {
                    "src": ["tag:gf-reapi-cell-egress"],
                    "dst": ["tag:gf-reapi-linux-worker"],
                    "ip": ["tcp:8981"],
                }),
                ("grants", {
                    "src": ["tag:gf-reapi-cell-egress"],
                    "dst": ["tag:gf-reapi-rocm-worker"],
                    "ip": ["tcp:8981"],
                }),
            ],
        )

    def test_gf_reapi_rocm_worker_route_is_single_port_and_tag_scoped(self) -> None:
        # TIN-5861 R-W23-20261009: the cell egress proxy may reach the ROCm
        # worker on 8981 only; no ssh, no other port, no reverse direction.
        tag = "tag:gf-reapi-rocm-worker"
        self.assertEqual(
            self.policy["tagOwners"][tag],
            ["tag:tag-authority", "autogroup:admin", "group:dollhouse-admins"],
        )
        references = [
            (surface, rule)
            for surface in ("acls", "grants", "ssh")
            for rule in self.policy[surface]
            if any(
                endpoint == tag or endpoint.startswith(f"{tag}:")
                for key in ("src", "dst")
                for endpoint in rule.get(key, [])
            )
        ]
        self.assertEqual(
            references,
            [("grants", {
                "src": ["tag:gf-reapi-cell-egress"],
                "dst": [tag],
                "ip": ["tcp:8981"],
            })],
        )
        # tcp:22 (and anything but 8981) from cell egress to the worker is
        # not granted by any rule.
        allowed = {
            ip
            for row in self.policy["grants"]
            if "tag:gf-reapi-cell-egress" in row["src"] and tag in row["dst"]
            for ip in row.get("ip", [])
        }
        self.assertEqual(allowed, {"tcp:8981"})
        self.assertNotIn("tcp:22", allowed)
        self.assertNotIn("*", allowed)
        for row in self.policy["acls"]:
            self.assertFalse(
                "tag:gf-reapi-cell-egress" in row["src"]
                and any(d.startswith(tag) for d in row["dst"])
            )
        for rule in self.policy["ssh"]:
            self.assertNotIn(tag, rule["src"] + rule["dst"])

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
        # The tailnet-acl#29 grants, the TIN-4686 device twins and the honey
        # and bumble tcp:8080 grant (TIN-4655) are the only grants whose
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


    # GFTB tsidp, the Cloudflare Access IdP for the members gate (operator
    # rulings 2026-10-03: "lets design and implement both in ultracode";
    # "this is the intent; I can add users to the qa tag as needed"; "Fix
    # both, then I review"). Lab design
    # docs/operations/TAILNET_MEMBERSHIP_DETECTION_DESIGN_2026-10-03.md 4.3.
    #
    # Merging applies, so the change is safe by construction: the IdP node
    # gets a NEW tag, tag:gftb-idp, that no device holds, and every rule that
    # admits people keys on the one QA group, group:gftb-qa. tag:tsidp is
    # held by several existing devices (neo's netmap 2026-10-03: neo,
    # rj-gateway, setec-1, tsidp, tsidp-1, blahaj-doks-router), so its legacy
    # rules are left exactly as on main and pinned below.
    IDP = "tag:gftb-idp"
    QA_GROUP = "group:gftb-qa"
    TSIDP_CAP = "tailscale.com/cap/tsidp"
    IDP_GRANTS = [
        {
            "src": ["group:dollhouse-admins"],
            "dst": ["tag:gftb-idp"],
            "app": {"tailscale.com/cap/tsidp": [{"allow_admin_ui": True}]},
        },
        {
            "src": ["group:gftb-qa"],
            "dst": ["tag:gftb-idp"],
            "app": {"tailscale.com/cap/tsidp": [{
                "extraClaims": {"gftb_member": "true"},
                "includeInUserInfo": True,
            }]},
        },
        {
            "src": ["group:gftb-qa"],
            "dst": ["tag:gftb-idp"],
            "ip": ["tcp:443"],
        },
        # TIN-5371: neo reaches the IdP and may use its admin endpoints; no
        # member capability, no allow_dcr, no extraClaims.
        {
            "src": ["tinyland-neo"],
            "dst": ["tag:gftb-idp"],
            "ip": ["tcp:443"],
        },
        {
            "src": ["tinyland-neo"],
            "dst": ["tag:gftb-idp"],
            "app": {"tailscale.com/cap/tsidp": [{"allow_admin_ui": True}]},
        },
        # Tagged identity for the neo host (TIN-5371): the claim and the
        # identity come from policy; the patched tsidp reads taggedIdentity.
        {
            "src": ["tinyland-neo"],
            "dst": ["tag:gftb-idp"],
            "app": {"tailscale.com/cap/tsidp": [{
                "extraClaims": {"gftb_member": "true"},
                "includeInUserInfo": True,
                "taggedIdentity": {
                    "email": "jess@sulliwood.org",
                    "name": "Jess Sullivan",
                    "subject": "16908883666124",
                },
            }]},
        },
    ]
    # Every rule naming tag:tsidp, exactly as on main (1342ef0). Retiring
    # them is a separate change after those devices are retagged.
    LEGACY_TSIDP_ACLS = [
        {
            "action": "accept",
            "src": ["tag:dev"],
            "dst": ["tag:dollhouse:*", "tag:services:*", "tag:k8s:*", "tag:tsidp:*", "autogroup:internet:*"],
        },
        {"action": "accept", "src": ["group:dollhouse-admins", "tag:k8s"], "dst": ["tag:tsidp:*"]},
    ]
    LEGACY_TSIDP_GRANTS = [
        {
            "src": ["tag:tsidp"],
            "dst": ["group:dollhouse-admins"],
            "app": {"tailscale.com/cap/tsidp": [{"admin": ["group:dollhouse-admins"]}]},
        },
    ]

    @staticmethod
    def _names(row):
        """Every identity a rule names: sources, and destinations without
        the ACL port suffix (grants carry ports in "ip" instead)."""
        dst = [entry.rsplit(":", 1)[0] for entry in row["dst"]] if "action" in row else list(row["dst"])
        return set(row["src"]) | set(dst)

    @staticmethod
    def _dst(row):
        return {entry.rsplit(":", 1)[0] for entry in row["dst"]} if "action" in row else set(row["dst"])

    def test_gftb_idp_grants_are_exact_and_current_schema(self) -> None:
        self.assertEqual(
            [row for row in self.policy["grants"] if self.IDP in row["src"] + row["dst"]],
            self.IDP_GRANTS,
        )
        self.assertFalse([row for row in self.policy["acls"] if self.IDP in self._names(row)])

    def test_gftb_member_claim_holders_and_tagged_identity_are_host_only(self) -> None:
        def rules(row):
            return row.get("app", {}).get(self.TSIDP_CAP, [])
        claim = [r["src"] for r in self.policy["grants"] if any("extraClaims" in x for x in rules(r))]
        self.assertEqual(claim, [[self.QA_GROUP], ["tinyland-neo"]])
        tagged = [r["src"] for r in self.policy["grants"] if any("taggedIdentity" in x for x in rules(r))]
        self.assertEqual(tagged, [["tinyland-neo"]])

    def test_allow_admin_ui_holders_are_the_admins_group_and_neo(self) -> None:
        holders = [
            row["src"] for row in self.policy["grants"]
            if any(c.get("allow_admin_ui") for c in row.get("app", {}).get(self.TSIDP_CAP, []))
        ]
        self.assertEqual(holders, [["group:dollhouse-admins"], ["tinyland-neo"], ["group:dollhouse-admins"]])

    def test_gftb_idp_change_leaves_every_existing_device_unaffected(self) -> None:
        """No device that exists today gains or loses anything on merge.

        tag:gftb-idp is new (no device holds it), so a rule whose only
        destination is that tag changes reach only to a node that does not
        exist yet; its sources are user groups, which never match a tagged
        device, so no tagged device gains outbound access. The Funnel attr
        targets that tag alone. group:gftb-qa appears only as a source
        toward new tags, so adding a person to it grants nothing else.
        """
        new_tags = {self.IDP, "tag:gftb-probe"}
        for row in self.policy["acls"] + self.policy["grants"]:
            if self.IDP in self._names(row):
                self.assertEqual(row["dst"], [self.IDP], row)
                self.assertTrue(all(src.startswith("group:") or src == "tinyland-neo" for src in row["src"]), row)
            if self.QA_GROUP in row["src"]:
                self.assertTrue(self._dst(row) <= new_tags, row)
            self.assertNotIn(self.QA_GROUP, row["dst"])
            self.assertNotIn(self.IDP, row["src"])
        attrs = [row for row in self.policy["nodeAttrs"] if self.IDP in row["target"]]
        self.assertEqual(attrs, [{"target": [self.IDP], "attr": ["funnel"]}])
        for row in self.policy["ssh"]:
            self.assertNotIn(self.IDP, row["src"] + row["dst"])
            self.assertNotIn(self.QA_GROUP, row["src"] + row["dst"])
        self.assertNotIn(self.IDP, self.policy["autoApprovers"]["exitNode"])
        self.assertFalse(any(self.IDP in tags for tags in self.policy["autoApprovers"]["routes"].values()))
        self.assertEqual(self.policy["tagOwners"][self.IDP], ["autogroup:admin"])
        self.assertFalse([tag for tag, owners in self.policy["tagOwners"].items() if self.IDP in owners or self.QA_GROUP in owners])
        self.assertNotIn(self.IDP, self.policy["hosts"])

    def test_legacy_tag_tsidp_rules_are_unchanged_from_main(self) -> None:
        self.assertEqual(
            [row for row in self.policy["acls"] if "tag:tsidp" in self._names(row)],
            self.LEGACY_TSIDP_ACLS,
        )
        self.assertEqual(
            [row for row in self.policy["grants"] if "tag:tsidp" in row["src"] + row["dst"]],
            self.LEGACY_TSIDP_GRANTS,
        )
        self.assertFalse(any("tag:tsidp" in row["target"] for row in self.policy["nodeAttrs"]))
        self.assertEqual(
            self.policy["tagOwners"]["tag:tsidp"],
            ["tag:tag-authority", "autogroup:admin", "group:dollhouse-admins"],
        )

    def test_tag_dev_and_tag_k8s_have_no_path_to_the_idp_node(self) -> None:
        # The design narrows tag:dev and tag:k8s away from the IdP. With the
        # IdP on tag:gftb-idp, neither reaches it by any rule; their legacy
        # tag:tsidp:* reach stays with the devices that hold tag:tsidp today.
        for row in self.policy["acls"] + self.policy["grants"]:
            if {"tag:dev", "tag:k8s"} & set(row["src"]):
                self.assertNotIn(self.IDP, self._dst(row), row)
        # Nor does any rule through a destination wide enough to cover a
        # tagged node (see also the CIDR and hosts check for gftb-probe).
        universal = {"*", "autogroup:tagged", "0.0.0.0/0", "::/0", "100.64.0.0/10"}
        for row in self.policy["acls"] + self.policy["grants"]:
            self.assertFalse(universal & self._dst(row), row)

    def test_tsidp_capability_is_least_privilege(self) -> None:
        for grant in self.policy["grants"]:
            for rule in grant.get("app", {}).get(self.TSIDP_CAP, []):
                self.assertNotIn("allow_dcr", rule)
                # No STS or RFC 8707 audience for anyone: the token audience
                # is only the requesting client, the static Access client.
                self.assertNotIn("users", rule)
                self.assertNotIn("resources", rule)
                if grant["dst"] == [self.IDP]:
                    self.assertNotIn("admin", rule)
                if rule.get("allow_admin_ui"):
                    self.assertIn(grant["src"], (["group:dollhouse-admins"], ["tinyland-neo"]))
                if "taggedIdentity" in rule:
                    # Only host grants; subject and email never ride extraClaims.
                    self.assertEqual(grant["src"], ["tinyland-neo"])
                    self.assertEqual(set(rule["taggedIdentity"]), {"subject", "email", "name"})
                    self.assertTrue(all(isinstance(v, str) and v for v in rule["taggedIdentity"].values()))
                    self.assertEqual(rule["taggedIdentity"]["email"], "jess@sulliwood.org")
                    # Operator ruling 2026-10-05, "Numeric WhoIs user id": the id
                    # tsidp uses as sub for the operator's user-owned devices.
                    self.assertRegex(rule["taggedIdentity"]["subject"], r"^[0-9]+$")
                    self.assertFalse({"sub", "subject", "email", "name"} & set(rule.get("extraClaims", {})))
                if "extraClaims" in rule:
                    self.assertIn(grant["src"], ([self.QA_GROUP], ["tinyland-neo"]))
                    # A JSON string, exactly the Access group claim_value.
                    self.assertEqual(rule["extraClaims"], {"gftb_member": "true"})

    # Tailnet-only tsidp for pods (TIN-5669 / TIN-5587; operator ruling
    # R-TSIDP-TAILNET-20261006: tailnet-only, reviewed ACL grant, no Funnel and
    # no public exposure). tag:infra-idp is new and admin-owned, so no device
    # holds it today; the grants take effect only for a node the operator
    # enrols later. The name is pending plan section 5 question 1.
    INFRA_IDP = "tag:infra-idp"
    INFRA_IDP_GRANTS = [
        {
            "src": ["group:dollhouse-admins", "tag:k8s"],
            "dst": ["tag:infra-idp"],
            "ip": ["tcp:443"],
        },
        {
            "src": ["group:dollhouse-admins"],
            "dst": ["tag:infra-idp"],
            "app": {"tailscale.com/cap/tsidp": [{"allow_admin_ui": True}]},
        },
    ]

    def test_infra_idp_grants_are_exact_and_tailnet_only(self) -> None:
        self.assertEqual(
            [row for row in self.policy["grants"] if self.INFRA_IDP in row["src"] + row["dst"]],
            self.INFRA_IDP_GRANTS,
        )
        self.assertFalse([row for row in self.policy["acls"] if self.INFRA_IDP in self._names(row)])
        self.assertEqual(self.policy["tagOwners"][self.INFRA_IDP], ["autogroup:admin"])
        # No Funnel for the tag, directly or through any other target.
        for row in self.policy["nodeAttrs"]:
            if "funnel" in row["attr"]:
                self.assertNotIn(self.INFRA_IDP, row["target"], row)
                self.assertFalse({"*", "autogroup:tagged", "autogroup:member"} & set(row["target"]), row)
        for row in self.policy["ssh"]:
            self.assertNotIn(self.INFRA_IDP, row["src"] + row["dst"])
        self.assertNotIn(self.INFRA_IDP, self.policy["autoApprovers"]["exitNode"])
        self.assertFalse(any(self.INFRA_IDP in tags for tags in self.policy["autoApprovers"]["routes"].values()))
        self.assertNotIn(self.INFRA_IDP, self.policy["hosts"])
        self.assertFalse([t for t, owners in self.policy["tagOwners"].items() if self.INFRA_IDP in owners])

    def test_infra_idp_is_separate_from_the_gftb_idp_and_legacy_tsidp(self) -> None:
        for row in self.policy["acls"] + self.policy["grants"]:
            if self.INFRA_IDP in self._names(row):
                self.assertNotIn(self.IDP, self._names(row), row)
                self.assertNotIn("tag:tsidp", self._names(row), row)
                self.assertNotIn(self.QA_GROUP, self._names(row), row)
        for rule_row in self.policy["grants"]:
            for rule in rule_row.get("app", {}).get(self.TSIDP_CAP, []):
                if rule_row["dst"] == [self.INFRA_IDP]:
                    self.assertEqual(set(rule), {"allow_admin_ui"})

    def test_k8s_operator_connector_routes_are_approved_and_reachable(self) -> None:
        routes = self.policy["autoApprovers"]["routes"]
        for cidr in ("10.244.0.0/16", "10.245.0.0/16"):
            self.assertEqual(routes[cidr], ["tag:k8s-operator"])
        self.assertEqual(
            [row for row in self.policy["acls"] if "10.244.0.0/16:*" in row["dst"]],
            [
                {
                    "action": "accept",
                    "src": ["group:dollhouse-admins", "tag:dev"],
                    "dst": ["10.244.0.0/16:*", "10.245.0.0/16:*"],
                }
            ],
        )

    def test_idp_reach_is_the_qa_group_and_the_neo_host(self) -> None:
        reach = [row for row in self.policy["grants"] if row["dst"] == [self.IDP] and "ip" in row]
        self.assertEqual(
            reach,
            [
                {"src": [self.QA_GROUP], "dst": [self.IDP], "ip": ["tcp:443"]},
                {"src": ["tinyland-neo"], "dst": [self.IDP], "ip": ["tcp:443"]},
            ],
        )
        self.assertEqual(self.policy["groups"][self.QA_GROUP], ["jsullivan2@gmail.com", "jess@sulliwood.org"])

    def test_funnel_only_for_dollhouse_and_gftb_idp(self) -> None:
        funnel = [row for row in self.policy["nodeAttrs"] if "funnel" in row["attr"]]
        self.assertEqual(
            funnel,
            [
                {"target": ["tag:dollhouse"], "attr": ["funnel"]},
                {"target": [self.IDP], "attr": ["funnel"]},
            ],
        )

    # R-C557 (TIN-6192 comment 94eb75c0) and R-C560 (TIN-6192 comment
    # aa9f7910). honey's Tailscale operator API server proxy
    # (ts-operator-honey, tag:k8s-operator, listening on :443) reads
    # tailscale.com/cap/kubernetes from WhoIs of the caller, so a cap only
    # reaches the proxy through a grant whose src is the caller and whose dst
    # is the proxy tag. The CI row below is inert until blahaj sets
    # apiServerProxyConfig.mode to "true" (auth mode).
    K8S_CAP = "tailscale.com/cap/kubernetes"
    CI_EPHEMERAL = "tag:tinyland-lab-ci-ephemeral"
    K8S_OPERATOR = "tag:k8s-operator"

    def _kubernetes_cap_grants(self) -> list:
        return [row for row in self.policy["grants"] if self.K8S_CAP in row.get("app", {})]

    def test_kubernetes_cap_grants_are_exactly_the_ci_row(self) -> None:
        # R-C560 "Delete it (Recommended)": the reversed system:masters row is
        # gone, so the CI grant (R-C557, R-C561 "Keep the tag") is the only
        # kubernetes-cap grant.
        self.assertEqual(
            self._kubernetes_cap_grants(),
            [
                {
                    "src": [self.CI_EPHEMERAL],
                    "dst": [self.K8S_OPERATOR],
                    "app": {self.K8S_CAP: [{"impersonate": {"groups": ["adi-sms-deployers"]}}]},
                    "ip": ["tcp:443"],
                },
            ],
        )

    def test_no_grant_carries_system_masters(self) -> None:
        # R-C560: cluster-admin stays on direct :6443 with a kubeconfig. No
        # grant on any surface, in any direction or cap, names system:masters.
        for row in self.policy["grants"]:
            self.assertNotIn("system:masters", json.dumps(row), row)
        self.assertNotIn("system:masters", json.dumps(self.policy))

    def test_ci_proxy_grant_is_tcp_443_and_one_namespaced_group(self) -> None:
        # R-C557: the CI tag reaches the proxy on tcp:443 only, impersonated
        # as adi-sms-deployers only, and no other surface gives it the proxy
        # tag, the cap, or a new destination.
        ci_rows = [
            (surface, row)
            for surface in ("acls", "grants", "ssh")
            for row in self.policy[surface]
            if self.CI_EPHEMERAL in row["src"]
        ]
        self.assertEqual(
            ci_rows,
            [
                ("acls", {
                    "action": "accept",
                    "src": [self.CI_EPHEMERAL, "tag:tinyland-lab-deploy"],
                    "dst": ["tag:dev:22", "tag:tinyland-lab-common:22"],
                }),
                ("acls", {"action": "accept", "src": [self.CI_EPHEMERAL], "dst": ["tag:dev:*"]}),
                ("grants", {
                    "src": [self.CI_EPHEMERAL],
                    "dst": [self.K8S_OPERATOR],
                    "app": {self.K8S_CAP: [{"impersonate": {"groups": ["adi-sms-deployers"]}}]},
                    "ip": ["tcp:443"],
                }),
                ("ssh", {
                    "action": "accept",
                    "src": [self.CI_EPHEMERAL, "tag:tinyland-lab-deploy"],
                    "dst": ["tag:dev", "tag:tinyland-lab-common"],
                    "users": ["jsullivan2", "jess", "autogroup:nonroot"],
                }),
            ],
        )
        self.assertFalse(any(self.CI_EPHEMERAL in row["dst"] for row in self.policy["grants"]))

    def test_only_operator_user_groups_and_the_ci_tag_reach_the_proxy_tag(self) -> None:
        # blahaj condition 5 (TIN-6192 2e02c184): no broader rule already
        # reaches tag:k8s-operator. Tagged callers without a cap would be
        # impersonated with their tags as groups, so any new tagged source
        # here needs its own review.
        reaching = []
        for surface in ("acls", "grants"):
            for row in self.policy[surface]:
                if any(d == self.K8S_OPERATOR or d.startswith(self.K8S_OPERATOR + ":") or d.startswith("*")
                       for d in row["dst"]):
                    reaching.append((surface, row["src"]))
        self.assertEqual(
            reaching,
            [
                ("acls", ["group:dollhouse-admins", "group:dollhouse-users"]),
                ("grants", [self.CI_EPHEMERAL]),
            ],
        )

    def test_policy_tests_pin_ci_proxy_reach_and_closed_apiserver_hosts(self) -> None:
        tests = self.policy["tests"]
        self.assertEqual(
            tests,
            [
                {
                    "src": self.CI_EPHEMERAL,
                    "proto": "tcp",
                    "accept": ["tag:k8s-operator:443", "tag:dev:22"],
                    "deny": [
                        "tinyland-honey:6443",
                        "tinyland-honey:443",
                        "tinyland-bumble:6443",
                        "tinyland-sting:6443",
                    ],
                },
                {
                    "src": "tag:tinyland-lab-deploy",
                    "proto": "tcp",
                    "accept": ["tag:dev:22"],
                    "deny": ["tag:k8s-operator:443", "tinyland-honey:6443"],
                },
                {
                    "src": self.PRINTSTACK,
                    "proto": "tcp",
                    "accept": ["tinyland-mbp-13:443"],
                    "deny": [
                        "tinyland-mbp-13:7125",
                        "tinyland-mbp-13:22",
                        "tinyland-honey:6443",
                    ],
                },
                {
                    "src": "jess@sulliwood.org",
                    "proto": "tcp",
                    "accept": ["tag:printstack:443"],
                    "deny": ["tag:printstack:22"],
                },
                *self.SOFTPROXY_POLICY_TESTS,
                self.MX_RELAY_POLICY_TEST,
                self.HONEY_TO_RELAY_POLICY_TEST,
                self.NEO_TO_RELAY_POLICY_TEST,
                self.ADMIN_USER_TO_RELAY_POLICY_TEST,
                self.EXPORTER_EGRESS_POLICY_TEST,
                *self.POST_RETAG_RATCHET_TESTS,
            ],
        )
        # Every field is set, so the post-write read-back cannot drop an
        # empty key and change the canonical digest.
        for entry in tests:
            self.assertEqual(set(entry), {"src", "proto", "accept", "deny"})
            self.assertTrue(entry["accept"] and entry["deny"])
        hosts = self.policy["hosts"]
        for name in ("tinyland-honey", "tinyland-bumble", "tinyland-sting"):
            self.assertIn(name, hosts)

    # tag:printstack (R-GOLIVE-20261020-c, operator 2026-10-20, TIN-6787:
    # "Approve the tag:printstack ACL change", narrow form). The honey
    # Tailscale operator mints the printstack Ingress and egress proxies with
    # it. Exactly two grants, both tcp:443: egress to mbp-13, and the
    # operator's devices plus the agent seats in to the Ingress proxies.
    PRINTSTACK = "tag:printstack"
    MBP_13 = "tinyland-mbp-13"
    PRINTSTACK_SEATS = ["tinyland-neo", "tinyland-sting", "tinyland-petting-zoo-mini"]

    def test_printstack_tag_is_owned_by_the_kubernetes_operator_like_mcp_proxy(self) -> None:
        self.assertEqual(
            self.policy["tagOwners"][self.PRINTSTACK],
            ["tag:k8s-operator", "autogroup:admin", "group:dollhouse-admins"],
        )
        # tag:k8s-operator ownership is not broadened by this change.
        self.assertEqual(
            self.policy["tagOwners"]["tag:k8s-operator"],
            ["tag:tag-authority", "tag:k8s-operator", "autogroup:admin", "group:dollhouse-admins"],
        )
        self.assertEqual(self.policy["hosts"][self.MBP_13], "100.122.197.52")
        for seat in self.PRINTSTACK_SEATS:
            self.assertIn(seat, self.policy["hosts"])

    def test_printstack_grants_are_exactly_two_tcp_443_rows(self) -> None:
        tag = self.PRINTSTACK
        references = [
            (surface, rule)
            for surface in ("acls", "grants", "ssh")
            for rule in self.policy[surface]
            if any(
                endpoint == tag or endpoint.startswith(f"{tag}:")
                for key in ("src", "dst")
                for endpoint in rule.get(key, [])
            )
        ]
        self.assertEqual(
            references,
            [
                ("grants", {"src": [tag], "dst": [self.MBP_13], "ip": ["tcp:443"]}),
                ("grants", {
                    "src": ["group:dollhouse-admins"] + self.PRINTSTACK_SEATS,
                    "dst": [tag],
                    "ip": ["tcp:443"],
                }),
            ],
        )
        # The mbp-13 alias is reached by nothing but the printstack egress row.
        self.assertEqual(
            [row for row in self.policy["grants"] if self.MBP_13 in row["dst"]],
            [{"src": [tag], "dst": [self.MBP_13], "ip": ["tcp:443"]}],
        )
        for rule in self.policy["acls"]:
            self.assertFalse(any(d.startswith(self.MBP_13 + ":") for d in rule["dst"]))
        for row in self.policy["nodeAttrs"]:
            self.assertNotIn(tag, row["target"])
        for tags in self.policy["autoApprovers"]["routes"].values():
            self.assertNotIn(tag, tags)

    # tag:softproxy (GO-02 step 1, Linear TIN-7729). xoxd-ai/softproxy SP-1
    # keeps it tailnet only with Funnel off, and SP-25 gives it its own
    # tailscale node. The one grant lets the operator's own untagged devices
    # and neo reach it on tcp:443. Jess works on neo, a tagged device no
    # group matches (Jess 2026-10-30, softproxy seat session, TIN-7729).
    # Nothing else names it, so it has no outbound reach, no Funnel, no SSH
    # and no autoApprover.
    SOFTPROXY = "tag:softproxy"
    SOFTPROXY_GRANT = {
        "src": ["group:dollhouse-admins", "tinyland-neo"],
        "dst": ["tag:softproxy"],
        "ip": ["tcp:443"],
    }
    SOFTPROXY_POLICY_TESTS = [
        {
            "src": "jess@sulliwood.org",
            "proto": "tcp",
            "accept": ["tag:softproxy:443"],
            "deny": [
                "tag:softproxy:80",
                "tag:softproxy:22",
                "tag:softproxy:8080",
                "tag:softproxy:43140",
            ],
        },
        {
            "src": "jsullivan2@gmail.com",
            "proto": "tcp",
            "accept": ["tag:softproxy:443"],
            "deny": ["tag:softproxy:80", "tag:softproxy:22"],
        },
        {
            "src": "tag:dev",
            "proto": "tcp",
            "accept": ["tag:dev:22"],
            "deny": ["tag:softproxy:443", "tag:softproxy:80"],
        },
        {
            "src": "tag:dollhouse",
            "proto": "tcp",
            "accept": ["tag:dollhouse:22"],
            "deny": ["tag:softproxy:443", "tag:softproxy:80"],
        },
        {
            "src": "tag:k8s-operator",
            "proto": "tcp",
            "accept": ["tag:k8s:443"],
            "deny": ["tag:softproxy:443", "tag:softproxy:80"],
        },
        {
            "src": "tag:mcp-proxy",
            "proto": "tcp",
            "accept": ["tag:mcp-proxy:3100"],
            "deny": ["tag:softproxy:443", "tag:softproxy:80"],
        },
        {
            "src": "tinyland-neo",
            "proto": "tcp",
            "accept": ["tag:softproxy:443"],
            "deny": [
                "tag:softproxy:80",
                "tag:softproxy:22",
                "tag:softproxy:8080",
                "tag:softproxy:43140",
            ],
        },
        {
            "src": "tinyland-sting",
            "proto": "tcp",
            "accept": ["tinyland-loki-observability:3100"],
            "deny": ["tag:softproxy:443", "tag:softproxy:80", "tag:softproxy:22"],
        },
    ]

    def test_softproxy_tag_is_admin_owned_and_owns_no_tag(self) -> None:
        tag = self.SOFTPROXY
        self.assertEqual(self.policy["tagOwners"][tag], ["autogroup:admin"])
        self.assertFalse([t for t, owners in self.policy["tagOwners"].items() if tag in owners])
        self.assertNotIn(tag, self.policy["hosts"])

    def test_softproxy_has_exactly_one_inbound_tcp_443_grant(self) -> None:
        tag = self.SOFTPROXY
        references = [
            (surface, rule)
            for surface in ("acls", "grants", "ssh")
            for rule in self.policy[surface]
            if any(
                endpoint == tag or endpoint.startswith(f"{tag}:")
                for key in ("src", "dst")
                for endpoint in rule.get(key, [])
            )
        ]
        self.assertEqual(references, [("grants", self.SOFTPROXY_GRANT)])
        # Exactly two sources: the operator's group and neo's host alias.
        self.assertEqual(len(references[0][1]["src"]), 2)
        # The host source is neo alone: its alias is one tailnet address.
        self.assertEqual(self.policy["hosts"]["tinyland-neo"], "100.67.93.34")
        # The source group is exactly the operator's two identities.
        self.assertEqual(
            self.policy["groups"]["group:dollhouse-admins"],
            ["jsullivan2@gmail.com", "jess@sulliwood.org"],
        )

    def test_softproxy_is_tailnet_only_with_no_node_attr_or_auto_approver(self) -> None:
        tag = self.SOFTPROXY
        for row in self.policy["nodeAttrs"]:
            self.assertNotIn(tag, row["target"], row)
            if "funnel" in row["attr"]:
                self.assertFalse({"*", "autogroup:tagged", "autogroup:member"} & set(row["target"]), row)
        for tags in self.policy["autoApprovers"]["routes"].values():
            self.assertNotIn(tag, tags)
        self.assertNotIn(tag, self.policy["autoApprovers"]["exitNode"])
        for tags in self.policy["autoApprovers"]["services"].values():
            self.assertNotIn(tag, tags)

    def test_no_wide_selector_reaches_softproxy(self) -> None:
        # The reference check sees only rules that name the tag. A "*" or
        # autogroup:tagged destination, or a tailnet CIDR wider than one
        # address, would reach the node without naming it.
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        for surface in ("acls", "grants"):
            for rule in self.policy[surface]:
                for endpoint in rule["dst"]:
                    host = endpoint.rpartition(":")[0] if surface == "acls" else endpoint
                    self.assertNotIn(host, {"*", "autogroup:tagged"}, rule)
                    try:
                        network = ipaddress.ip_network(host, strict=False)
                    except ValueError:
                        continue
                    if network.version == 4 and network.overlaps(cgnat):
                        self.assertEqual(network.num_addresses, 1, rule)
        for alias, address in self.policy["hosts"].items():
            network = ipaddress.ip_network(address, strict=False)
            if network.version == 4 and network.overlaps(cgnat):
                self.assertEqual(network.num_addresses, 1, alias)


if __name__ == "__main__":
    unittest.main()
