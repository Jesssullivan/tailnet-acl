"""Golden test: grants rendered from typed Dhall equal the raw grants.json.

grants.json is the frozen pre-migration snapshot of main. Equality is checked
three ways: JSON equality, byte equality of the serialized grants section the
build writes (same key reordering and tab indent as scripts/build.py), and
grant order. Once this passes on main, grants.json can be removed and this
test pointed at a committed golden copy, or deleted.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build  # noqa: E402


def serialize(grants: list) -> str:
    policy = build.reorder_policy({"grants": grants})
    return json.dumps(policy["grants"], indent="\t")


class TypedGrantsGoldenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        out = subprocess.run(
            ["dhall-to-json", "--file", str(ROOT / "policy.dhall")],
            capture_output=True, text=True, check=True, cwd=str(ROOT),
        ).stdout
        cls.rendered = json.loads(out)["grants"]
        cls.golden = json.loads((ROOT / "grants.json").read_text())

    def test_same_count_and_order(self) -> None:
        self.assertEqual(len(self.rendered), len(self.golden))
        for index, (a, b) in enumerate(zip(self.rendered, self.golden)):
            self.assertEqual(a, b, f"grant {index} differs")

    def test_json_equal(self) -> None:
        self.assertEqual(self.rendered, self.golden)

    def test_byte_identical_serialization(self) -> None:
        self.assertEqual(serialize(self.rendered), serialize(self.golden))

    def test_no_nulls_or_empty_optionals_leak(self) -> None:
        self.assertNotIn("null", serialize(self.rendered))

    def test_build_does_not_merge_raw_grants(self) -> None:
        self.assertFalse(hasattr(build, "GRANTS_JSON"))

    def test_unused_variants_render_to_expected_shapes(self) -> None:
        # Shapes of the pending probe and tsidp grants, to pin Cap rendering.
        expr = """
let G = ./types/Grant.dhall
let J = ./types/JSON.dhall
in  G.render
      [ G.cap [ "group:a" ] [ "tag:p" ] [ G.Cap.Probe { cap = "example.org/cap/probe", flag = "member" } ]
      , G.cap [ "group:a" ] [ "tag:i" ]
          [ G.Cap.Tsidp
              (   G.tsidpEmpty
                //  { extraClaims = Some [ { mapKey = "flag_member", mapValue = J.string "true" } ]
                    , includeInUserInfo = Some True
                    , allowAdminUI = Some True
                    , allowDCR = Some False
                    , users = Some [ "group:a" ]
                    , resources = Some [ "r" ]
                    }
              )
          ]
      , G.cap [ "group:a" ] [ "tag:i" ] [ G.Cap.Custom { name = "x/cap/y", json = J.array [ J.object [ { mapKey = "n", mapValue = J.number 1.0 } ] ] } ]
      ]
"""
        out = subprocess.run(
            ["dhall-to-json"], input=expr, capture_output=True, text=True, check=True, cwd=str(ROOT),
        ).stdout
        self.assertEqual(
            json.loads(out),
            [
                {"src": ["group:a"], "dst": ["tag:p"], "app": {"example.org/cap/probe": [{"member": True}]}},
                {"src": ["group:a"], "dst": ["tag:i"], "app": {"tailscale.com/cap/tsidp": [{
                    "extraClaims": {"flag_member": "true"}, "includeInUserInfo": True,
                    "allow_admin_ui": True, "allow_dcr": False, "users": ["group:a"], "resources": ["r"]}]}},
                {"src": ["group:a"], "dst": ["tag:i"], "app": {"x/cap/y": [{"n": 1}]}},
            ],
        )


if __name__ == "__main__":
    unittest.main()
