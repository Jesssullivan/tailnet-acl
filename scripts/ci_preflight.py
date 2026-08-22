#!/usr/bin/env python3
"""Fail fast, and legibly, when the Tailscale credential wiring is wrong.

This runs on the runner's system python3 before the Nix toolchain is installed,
so a missing or dead credential costs seconds rather than a full dev-shell
build followed by an opaque ``API error 401`` a few minutes later.

Every failure names the exact secret or variable, and the exact scope it has to
live in, so a rotation lands in the right place on the first attempt.

No credential value is ever printed -- only its kind, inferred from the prefix.
"""

import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ts_auth import resolve_bearer  # noqa: E402

TAILNET = "taila4c78d.ts.net"
API_BASE = f"https://api.tailscale.com/api/v2/tailnet/{TAILNET}"

SECRET_NAME = "TAILSCALE_API_KEY"
CLIENT_ID_VAR = "TS_OAUTH_CLIENT_ID"

# The CI `validate` job and the CD `deploy` job both declare
# `environment: production`, so both resolve their credentials from this one
# scope. Keep this string in sync with the `environment:` key in
# .github/workflows/ci.yml and .github/workflows/cd.yml.
SCOPE = 'the "production" environment (repo Settings -> Environments -> production)'

IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"


def _annotate(level: str, title: str, lines: "list[str]") -> None:
    """Emit a GitHub annotation (single line) plus readable stderr output."""
    sys.stdout.flush()
    if IN_ACTIONS:
        # Annotation bodies cannot contain raw newlines.
        print(f"::{level} title={title}::{' '.join(lines)}")
    print(f"{title}", file=sys.stderr)
    for line in lines:
        print(f"  {line}", file=sys.stderr)


def fail(title: str, *lines: str) -> int:
    _annotate("error", title, list(lines))
    return 1


def warn(title: str, *lines: str) -> None:
    _annotate("warning", title, list(lines))


def main() -> int:
    secret = os.environ.get(SECRET_NAME, "").strip()
    client_id = os.environ.get(CLIENT_ID_VAR, "").strip()

    if not secret:
        return fail(
            "Tailscale credential is not wired",
            f"{SECRET_NAME} is unset or empty in this job.",
            f"Create it as an ENVIRONMENT secret named {SECRET_NAME} in {SCOPE}.",
            "A repository-level secret of the same name is NOT what this job reads: "
            "the job declares `environment: production`, and an environment secret of "
            "the same name shadows the repository secret.",
        )

    if secret.startswith("tskey-client-"):
        kind = "OAuth client secret (tskey-client-...)"
        if not client_id:
            return fail(
                "Tailscale OAuth client id is missing",
                f"{SECRET_NAME} holds an OAuth client secret, which cannot be used as a "
                "bearer token on its own -- it has to be exchanged for an access token, "
                "and that exchange requires the client id.",
                f"Set a variable (not a secret; the client id is not sensitive) named "
                f"{CLIENT_ID_VAR} in {SCOPE}, under 'Environment variables'.",
                f"Alternatively, swap {SECRET_NAME} back to a direct API key "
                "(tskey-api-...), which needs no client id.",
            )
    elif secret.startswith("tskey-api-"):
        kind = "direct API key (tskey-api-...)"
        if client_id:
            warn(
                "TS_OAUTH_CLIENT_ID is set but unused",
                f"{SECRET_NAME} holds a direct API key, so {CLIENT_ID_VAR} is ignored. "
                "This is harmless, but it means the OAuth path is untested.",
            )
    else:
        kind = "unrecognised prefix"
        warn(
            "Tailscale credential has an unrecognised prefix",
            f"{SECRET_NAME} starts with neither 'tskey-api-' nor 'tskey-client-'. "
            "This is usually a truncated or mis-pasted value. The live probe below is "
            "the authority.",
        )

    print(f"Credential scope: {SCOPE}")
    print(f"Credential kind:  {kind}")
    print(f"{CLIENT_ID_VAR}:   {'set' if client_id else 'unset'}")

    try:
        bearer = resolve_bearer(secret)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        return fail(
            "Tailscale OAuth token exchange failed",
            f"The client_credentials grant returned HTTP {exc.code}: {detail}",
            f"Check that {CLIENT_ID_VAR} in {SCOPE} is the client id belonging to the "
            f"client secret currently stored in {SECRET_NAME} -- a mismatched pair fails "
            "here.",
        )
    except Exception as exc:  # noqa: BLE001 -- surfaced verbatim to the operator
        return fail("Tailscale token could not be resolved", str(exc))

    req = urllib.request.Request(f"{API_BASE}/acl")
    req.add_header("Authorization", f"Bearer {bearer}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        if exc.code == 401:
            return fail(
                "Tailscale credential is present but rejected (HTTP 401)",
                f"The API returned: {detail}",
                f"Rotate the value of the {SECRET_NAME} environment secret in {SCOPE}.",
                "Direct API keys (tskey-api-...) expire after at most 90 days. An "
                "ACL-scoped OAuth client secret (tskey-client-...) does not expire and is "
                f"the preferred replacement, but it additionally needs its client id in "
                f"the {CLIENT_ID_VAR} variable in {SCOPE}.",
                "See docs/ci-credentials.md for the rotation runbook.",
            )
        if exc.code == 403:
            return fail(
                "Tailscale credential is valid but lacks policy-file permission (HTTP 403)",
                f"The API returned: {detail}",
                "The API key or OAuth client must carry the 'policy_file' scope "
                "(Tailscale admin console -> Settings -> Keys / OAuth clients).",
            )
        return fail(
            f"Tailscale API probe failed (HTTP {exc.code})",
            detail,
            f"Probed {API_BASE}/acl.",
        )
    except urllib.error.URLError as exc:
        return fail("Could not reach the Tailscale API", str(exc.reason))

    print(f"Preflight OK: the credential authenticates against {TAILNET} (HTTP {status}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
