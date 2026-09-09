"""Resolve the existing production direct API key or OAuth pair without logging values."""

import os
import urllib.parse
import urllib.request

from policy_api import parse_object, request_bytes
from policy_source import PolicyError

OAUTH_TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"


def resolve_bearer(secret):
    if secret.startswith("tskey-api-"):
        return secret
    if not secret.startswith("tskey-client-"):
        raise PolicyError("TAILSCALE_API_KEY is missing or has an unsupported credential class")
    client_id = os.environ.get("TS_OAUTH_CLIENT_ID", "")
    if not client_id:
        raise PolicyError("production TS_OAUTH_CLIENT_ID is missing")
    data = urllib.parse.urlencode({"client_id": client_id, "client_secret": secret, "grant_type": "client_credentials"}).encode()
    request = urllib.request.Request(OAUTH_TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    status, body, _etag = request_bytes(request)
    if status != 200:
        raise PolicyError(f"OAuth exchange failed (HTTP {status})")
    token = parse_object(body).get("access_token")
    if not isinstance(token, str) or not token:
        raise PolicyError("OAuth response has no access token")
    return token
