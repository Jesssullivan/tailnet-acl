#!/usr/bin/env python3
"""Build the final Tailscale ACL policy JSON.

Runs dhall-to-json on policy.dhall, merges with grants.json,
reorders keys for readability, and writes to generated/policy.json.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_DHALL = REPO_ROOT / "policy.dhall"
GRANTS_JSON = REPO_ROOT / "grants.json"
OUTPUT_DIR = REPO_ROOT / "generated"
OUTPUT_FILE = OUTPUT_DIR / "policy.json"

# Key ordering that matches the Tailscale ACL convention
TOP_LEVEL_KEY_ORDER = [
    "groups",
    "tagOwners",
    "acls",
    "grants",
    "ssh",
    "nodeAttrs",
    "autoApprovers",
    "hosts",
]

ACL_RULE_KEY_ORDER = ["action", "src", "dst"]
SSH_RULE_KEY_ORDER = ["action", "src", "dst", "users"]
GRANT_KEY_ORDER = ["src", "dst", "app", "ip"]


def ordered_dict(d: dict, key_order: list[str]) -> dict:
    """Reorder dict keys according to key_order, then any remaining keys."""
    result = {}
    for k in key_order:
        if k in d:
            result[k] = d[k]
    for k in d:
        if k not in result:
            result[k] = d[k]
    return result


def reorder_policy(policy: dict) -> dict:
    """Reorder all keys in the policy for human-readable output."""
    result = {}

    for key in TOP_LEVEL_KEY_ORDER:
        if key not in policy:
            continue
        value = policy[key]

        if key == "acls":
            value = [ordered_dict(r, ACL_RULE_KEY_ORDER) for r in value]
        elif key == "ssh":
            value = [ordered_dict(r, SSH_RULE_KEY_ORDER) for r in value]
        elif key == "grants":
            value = [ordered_dict(r, GRANT_KEY_ORDER) for r in value]

        result[key] = value

    # Any unexpected top-level keys
    for key in policy:
        if key not in result:
            result[key] = policy[key]

    return result


def main() -> int:
    # Step 1: Run dhall-to-json
    print(f"Compiling {POLICY_DHALL} ...", file=sys.stderr)
    try:
        result = subprocess.run(
            ["dhall-to-json", "--file", str(POLICY_DHALL)],
            capture_output=True,
            text=True,
            check=True,
            cwd=str(REPO_ROOT),
        )
    except subprocess.CalledProcessError as e:
        print(f"dhall-to-json failed:\n{e.stderr}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print("dhall-to-json not found. Install with: nix-env -iA nixpkgs.dhall-json", file=sys.stderr)
        return 1

    dhall_output = json.loads(result.stdout)
    print(f"  -> {len(dhall_output.get('acls', []))} ACL rules", file=sys.stderr)
    print(f"  -> {len(dhall_output.get('ssh', []))} SSH rules", file=sys.stderr)

    # Step 2: Load grants.json
    print(f"Loading {GRANTS_JSON} ...", file=sys.stderr)
    with open(GRANTS_JSON) as f:
        grants = json.load(f)
    print(f"  -> {len(grants)} grants", file=sys.stderr)

    # Step 3: Merge
    policy = {**dhall_output, "grants": grants}

    # Step 4: Validate structure
    required_keys = {"groups", "tagOwners", "acls", "grants", "ssh", "nodeAttrs", "autoApprovers", "hosts"}
    missing = required_keys - set(policy.keys())
    if missing:
        print(f"ERROR: Missing required keys: {missing}", file=sys.stderr)
        return 1

    for rule in policy["acls"]:
        if "action" not in rule or "src" not in rule or "dst" not in rule:
            print(f"ERROR: ACL rule missing required fields: {rule}", file=sys.stderr)
            return 1

    for rule in policy["ssh"]:
        if "users" not in rule:
            print(f"ERROR: SSH rule missing 'users' field: {rule}", file=sys.stderr)
            return 1

    # Step 5: Reorder keys for readability
    policy = reorder_policy(policy)

    # Step 6: Write output
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(policy, f, indent="\t")
        f.write("\n")

    print(f"Wrote {OUTPUT_FILE}", file=sys.stderr)
    print(f"  groups:       {len(policy['groups'])}", file=sys.stderr)
    print(f"  tagOwners:    {len(policy['tagOwners'])}", file=sys.stderr)
    print(f"  acls:         {len(policy['acls'])}", file=sys.stderr)
    print(f"  grants:       {len(policy['grants'])}", file=sys.stderr)
    print(f"  ssh:          {len(policy['ssh'])}", file=sys.stderr)
    print(f"  nodeAttrs:    {len(policy['nodeAttrs'])}", file=sys.stderr)
    print(f"  hosts:        {len(policy['hosts'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
