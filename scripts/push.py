#!/usr/bin/env python3
"""Push the generated policy to the live Tailscale ACL.

Compares the generated policy with the live ACL, shows the diff,
and pushes only if --confirm is passed.

Requires: TAILSCALE_API_KEY environment variable
Tailnet: taila4c78d.ts.net
"""

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATED_POLICY = REPO_ROOT / "generated" / "policy.json"
TAILNET = "taila4c78d.ts.net"
API_BASE = f"https://api.tailscale.com/api/v2/tailnet/{TAILNET}"


def fetch_live_acl(api_key: str) -> dict:
    """Fetch the current ACL from the Tailscale API."""
    url = f"{API_BASE}/acl"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"API error {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)


def push_acl(api_key: str, policy: dict) -> bool:
    """Push an ACL policy to the Tailscale API."""
    url = f"{API_BASE}/acl"
    data = json.dumps(policy).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"Push failed (HTTP {e.code}):\n{body}", file=sys.stderr)
        return False


def summarize_diff(live: dict, local: dict) -> list[str]:
    """Produce a human-readable diff summary."""
    lines = []
    all_keys = sorted(set(list(live.keys()) + list(local.keys())))

    for key in all_keys:
        lv = live.get(key)
        dv = local.get(key)

        if lv == dv:
            continue

        if lv is None:
            lines.append(f"+ {key}: NEW (not in live)")
        elif dv is None:
            lines.append(f"- {key}: REMOVED (not in local)")
        elif isinstance(lv, list) and isinstance(dv, list):
            added = len(dv) - len(lv)
            if added > 0:
                lines.append(f"~ {key}: {len(lv)} -> {len(dv)} (+{added})")
            elif added < 0:
                lines.append(f"~ {key}: {len(lv)} -> {len(dv)} ({added})")
            else:
                lines.append(f"~ {key}: {len(lv)} entries changed")
        else:
            lines.append(f"~ {key}: changed")

    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Push Tailscale ACL policy")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Actually push the policy (without this flag, only shows diff)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without pushing",
    )
    args = parser.parse_args()

    api_key = os.environ.get("TAILSCALE_API_KEY")
    if not api_key:
        print("ERROR: TAILSCALE_API_KEY environment variable is required.", file=sys.stderr)
        return 1

    if not GENERATED_POLICY.exists():
        print(f"ERROR: {GENERATED_POLICY} does not exist. Run 'just build' first.", file=sys.stderr)
        return 1

    with open(GENERATED_POLICY) as f:
        local = json.load(f)

    print("Fetching live ACL ...", file=sys.stderr)
    live = fetch_live_acl(api_key)

    if live == local:
        print("No changes: local policy matches live ACL.", file=sys.stderr)
        return 0

    print("\nChanges to apply:", file=sys.stderr)
    diff_lines = summarize_diff(live, local)
    for line in diff_lines:
        print(f"  {line}", file=sys.stderr)

    if args.dry_run:
        print("\n(dry run, no changes made)", file=sys.stderr)
        return 0

    if not args.confirm:
        print(
            "\nTo apply these changes, run again with --confirm.",
            file=sys.stderr,
        )
        return 2

    print("\nPushing policy to Tailscale API ...", file=sys.stderr)
    if push_acl(api_key, local):
        print("Push successful.", file=sys.stderr)
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
