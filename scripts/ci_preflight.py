#!/usr/bin/env python3
"""Verify production credential custody with a bounded ACL GET and safe diagnostics."""

import os
import sys

from policy_api import fetch_live_acl
from policy_source import PolicyError
from ts_auth import resolve_bearer

SCOPE = 'the "production" environment (repo Settings -> Environments -> production)'


def main():
    try:
        bearer = resolve_bearer(os.environ.get("TAILSCALE_API_KEY", "").strip())
        fetch_live_acl(bearer)
    except PolicyError as exc:
        print("Credential preflight FAILED: " + str(exc), file=sys.stderr)
        print("Required custody: production TAILSCALE_API_KEY; production TS_OAUTH_CLIENT_ID for OAuth. See docs/ci-credentials.md.", file=sys.stderr)
        return 1
    print("Preflight OK: production credential can read the policy (HTTP 200).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
