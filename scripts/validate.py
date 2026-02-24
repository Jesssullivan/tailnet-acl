#!/usr/bin/env python3
"""Validate generated policy against the live Tailscale ACL.

Fetches the current ACL from the Tailscale API and compares it
to generated/policy.json, showing any differences.

Requires: TAILSCALE_API_KEY environment variable
Tailnet: taila4c78d.ts.net
"""

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


def compare_section(name: str, live: object, local: object) -> list[str]:
    """Compare a section and return a list of difference descriptions."""
    diffs = []

    if live == local:
        return diffs

    if isinstance(live, list) and isinstance(local, list):
        if len(live) != len(local):
            diffs.append(f"  count: live={len(live)}, local={len(local)}")

        for i, (l, d) in enumerate(zip(live, local)):
            if l != d:
                diffs.append(f"  [{i}] DIFFERS:")
                diffs.append(f"    live:  {json.dumps(l, separators=(',', ':'))}")
                diffs.append(f"    local: {json.dumps(d, separators=(',', ':'))}")

        if len(live) > len(local):
            for i in range(len(local), len(live)):
                diffs.append(f"  [{i}] ONLY IN LIVE: {json.dumps(live[i], separators=(',', ':'))}")
        elif len(local) > len(live):
            for i in range(len(live), len(local)):
                diffs.append(f"  [{i}] ONLY IN LOCAL: {json.dumps(local[i], separators=(',', ':'))}")

    elif isinstance(live, dict) and isinstance(local, dict):
        all_keys = sorted(set(list(live.keys()) + list(local.keys())))
        for k in all_keys:
            lv = live.get(k)
            dv = local.get(k)
            if lv != dv:
                if lv is None:
                    diffs.append(f"  key '{k}': ONLY IN LOCAL")
                elif dv is None:
                    diffs.append(f"  key '{k}': ONLY IN LIVE")
                else:
                    diffs.append(f"  key '{k}':")
                    diffs.append(f"    live:  {json.dumps(lv)}")
                    diffs.append(f"    local: {json.dumps(dv)}")
    else:
        diffs.append(f"  live:  {json.dumps(live)}")
        diffs.append(f"  local: {json.dumps(local)}")

    return diffs


def main() -> int:
    api_key = os.environ.get("TAILSCALE_API_KEY")
    if not api_key:
        print("ERROR: TAILSCALE_API_KEY environment variable is required.", file=sys.stderr)
        print("Get an API key at: https://login.tailscale.com/admin/settings/keys", file=sys.stderr)
        return 1

    if not GENERATED_POLICY.exists():
        print(f"ERROR: {GENERATED_POLICY} does not exist. Run 'just build' first.", file=sys.stderr)
        return 1

    print(f"Loading local policy from {GENERATED_POLICY} ...", file=sys.stderr)
    with open(GENERATED_POLICY) as f:
        local = json.load(f)

    print(f"Fetching live ACL from {TAILNET} ...", file=sys.stderr)
    live = fetch_live_acl(api_key)

    # Compare all sections
    all_keys = sorted(set(list(live.keys()) + list(local.keys())))
    has_diff = False

    for key in all_keys:
        if key not in local:
            print(f"{key}: ONLY IN LIVE")
            has_diff = True
            continue
        if key not in live:
            print(f"{key}: ONLY IN LOCAL")
            has_diff = True
            continue

        diffs = compare_section(key, live[key], local[key])
        if diffs:
            print(f"{key}: MISMATCH")
            for d in diffs:
                print(d)
            has_diff = True
        else:
            print(f"{key}: OK")

    if has_diff:
        print("\nValidation FAILED: local policy differs from live.", file=sys.stderr)
        return 1
    else:
        print("\nValidation PASSED: local policy matches live ACL.", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
