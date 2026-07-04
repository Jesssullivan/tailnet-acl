"""Resolve a Tailscale API bearer token from the TAILSCALE_API_KEY value.

Accepts either form in TAILSCALE_API_KEY:

- A direct admin API key (``tskey-api-...``) — used as the bearer token as-is.
  These expire (max 90 days), so they are only suitable as an interim.
- An OAuth client secret (``tskey-client-...``) — non-expiring. Tailscale does
  NOT accept the client secret directly as a bearer token (HTTP 403), so it is
  exchanged for a short-lived access token via the ``client_credentials`` grant.
  Prefer an ACL-scoped OAuth client for least privilege.

This lets CD use a non-expiring, least-privilege OAuth client without any other
change to push.py / validate.py.
"""

import json
import os
import urllib.parse
import urllib.request

OAUTH_TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"


def resolve_bearer(secret: str) -> str:
    """Return a usable bearer token for the Tailscale API.

    Direct API keys are returned unchanged; OAuth client secrets are exchanged
    for an access token. The exchange requires the (non-secret) client id in
    TS_OAUTH_CLIENT_ID — Tailscale's token endpoint rejects requests without it.
    """
    if not secret or not secret.startswith("tskey-client-"):
        return secret

    client_id = os.environ.get("TS_OAUTH_CLIENT_ID", "")
    if not client_id:
        raise RuntimeError(
            "TAILSCALE_API_KEY holds an OAuth client secret (tskey-client-...) "
            "but TS_OAUTH_CLIENT_ID is unset; the token exchange requires the "
            "client id. Set the TS_OAUTH_CLIENT_ID Actions variable (it is not "
            "a secret) alongside the client-secret swap."
        )

    data = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": secret,
            "grant_type": "client_credentials",
        }
    ).encode()
    req = urllib.request.Request(OAUTH_TOKEN_URL, data=data)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=30) as resp:
        token = json.loads(resp.read().decode()).get("access_token")
    if not token:
        raise RuntimeError("OAuth token exchange returned no access_token")
    return token
