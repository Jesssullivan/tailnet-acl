import ipaddress
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONSTANTS = ROOT / "constants.dhall"
CORE = ROOT / "fragments" / "core.dhall"
GRANTS = ROOT / "grants.json"
FRAGMENTS = ROOT / "fragments"
AUTHORITY_DOC = ROOT / "docs" / "rke2-egress-authority.md"

TAG = "tag:rke2-egress"
HONEY = "tinyland-honey"
HONEY_IP = "100.113.89.12"
EXPECTED_GRANT = {
    "src": [TAG],
    "dst": [HONEY],
    "ip": ["tcp:6443", "tcp:9345"],
}


class Rke2EgressSourceContractTest(unittest.TestCase):
    def test_tag_constant_is_defined_once(self) -> None:
        constants = CONSTANTS.read_text(encoding="utf-8")
        self.assertEqual(constants.count('rke2_egress = "tag:rke2-egress"'), 1)
        literal_uses = [
            path.relative_to(ROOT).as_posix()
            for path in sorted(ROOT.rglob("*.dhall"))
            for _ in range(path.read_text(encoding="utf-8").count(TAG))
        ]
        self.assertEqual(literal_uses, ["constants.dhall"])

    def test_tag_owners_are_exact(self) -> None:
        core = CORE.read_text(encoding="utf-8")
        self.assertEqual(core.count("mapKey = C.tag.rke2_egress"), 1)
        owner_block = re.compile(
            r"""
            \{\s*mapKey\s*=\s*C\.tag\.rke2_egress
            \s*,\s*mapValue\s*=
            \s*\[\s*C\.tag\.k8s_operator
            \s*,\s*C\.autogroup\.admin
            \s*,\s*C\.group\.dollhouse_admins
            \s*\]\s*\}
            """,
            re.VERBOSE,
        )
        self.assertEqual(len(owner_block.findall(core)), 1)

    def test_tag_has_no_legacy_acl_authority(self) -> None:
        uses = []
        for path in sorted(ROOT.rglob("*.dhall")):
            count = path.read_text(encoding="utf-8").count("C.tag.rke2_egress")
            uses.extend([path.relative_to(ROOT).as_posix()] * count)
        self.assertEqual(uses, ["fragments/core.dhall"])

    def test_transport_grant_is_exact_and_unique(self) -> None:
        grants = json.loads(GRANTS.read_text(encoding="utf-8"))
        related = [
            grant
            for grant in grants
            if TAG in grant.get("src", []) or TAG in grant.get("dst", [])
        ]
        self.assertEqual(related, [EXPECTED_GRANT])

    def test_no_new_direct_rule_can_target_honey(self) -> None:
        grants = json.loads(GRANTS.read_text(encoding="utf-8"))

        def destination_includes_honey(destination: str) -> bool:
            if destination in {HONEY, HONEY_IP, "*"}:
                return True
            try:
                return ipaddress.ip_address(HONEY_IP) in ipaddress.ip_network(
                    destination,
                    strict=False,
                )
            except ValueError:
                return False

        self.assertTrue(destination_includes_honey("*"))
        self.assertTrue(destination_includes_honey("100.64.0.0/10"))
        direct_honey_grants = [
            grant
            for grant in grants
            if any(
                destination_includes_honey(dst)
                for dst in grant.get("dst", [])
            )
        ]
        self.assertEqual(direct_honey_grants, [EXPECTED_GRANT])

        legacy_sources = [
            ROOT / "policy.dhall",
            *sorted(FRAGMENTS.rglob("*.dhall")),
        ]
        direct_control_plane_destination = re.compile(
            rf"(?:{re.escape(HONEY)}|{re.escape(HONEY_IP)}):(?:\*|6443|9345)"
        )
        for forbidden in (
            f"{HONEY}:*",
            f"{HONEY}:6443",
            f"{HONEY_IP}:9345",
        ):
            self.assertIsNotNone(
                direct_control_plane_destination.fullmatch(forbidden)
            )
        matches = {
            path.relative_to(ROOT).as_posix(): direct_control_plane_destination.findall(
                path.read_text(encoding="utf-8")
            )
            for path in legacy_sources
        }
        self.assertEqual(
            {path: values for path, values in matches.items() if values},
            {},
        )

    def test_docs_preserve_mutable_tag_membership_proof_boundary(self) -> None:
        source = AUTHORITY_DOC.read_text(encoding="utf-8")
        self.assertIn("does **not** prove\nHoney-wide exclusivity", source)
        for tag in ("tag:dollhouse", "tag:subnet-router", "tag:switch"):
            self.assertIn(f"`{tag}`", source)
        self.assertIn("separately attended live preflight", source)
        self.assertIn(
            "cannot prove facts about mutable live device-tag membership",
            source,
        )

    def test_sensitive_source_literal_census_is_closed(self) -> None:
        policy_sources = [
            ROOT / "constants.dhall",
            GRANTS,
            *sorted(FRAGMENTS.rglob("*.dhall")),
        ]
        occurrences = {
            needle: [
                path.relative_to(ROOT).as_posix()
                for path in policy_sources
                for _ in range(path.read_text(encoding="utf-8").count(needle))
            ]
            for needle in (HONEY, HONEY_IP, "6443", "9345")
        }
        self.assertEqual(
            occurrences,
            {
                HONEY: [
                    "grants.json",
                    "grants.json",
                    "fragments/kubernetes.dhall",
                    "fragments/kubernetes.dhall",
                    "fragments/kubernetes.dhall",
                ],
                HONEY_IP: ["constants.dhall"],
                "6443": [
                    "grants.json",
                    "fragments/kubernetes.dhall",
                ],
                "9345": [
                    "grants.json",
                    "fragments/kubernetes.dhall",
                ],
            },
        )


if __name__ == "__main__":
    unittest.main()
