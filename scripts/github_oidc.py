"""Bounded, memory-only GitHub OIDC exchange; no legacy credential fallback."""

import base64
import os
from pathlib import Path
import urllib.parse
import urllib.request

from oidc_identity import identifier, load_manifest, token_text
from policy_api import parse_object, request_bytes
from policy_source import PolicyError, ROOT, head_revision, require_revision, strict_json_loads

TOKEN_EXCHANGE = "https://api.tailscale.com/api/v2/oauth/token-exchange"
MAX_TOKEN_BODY = 65536


def trusted_context(role, environment=None, event=None, root=ROOT):
    env = os.environ if environment is None else environment
    identities, _digest = load_manifest()
    if role not in identities:
        raise PolicyError("unknown federated role")
    rules = identities[role]["customClaimRules"]
    checks = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": rules["repository"],
              "GITHUB_REPOSITORY_ID": rules["repository_id"], "GITHUB_REPOSITORY_OWNER_ID": rules["repository_owner_id"],
              "GITHUB_REF": rules["ref"], "GITHUB_EVENT_NAME": rules["event_name"], "GITHUB_WORKFLOW_REF": rules["workflow_ref"]}
    if any(env.get(key) != value for key, value in checks.items()):
        raise PolicyError("GitHub context is outside the reviewed federated trust")
    workflow_sha = require_revision(env.get("GITHUB_WORKFLOW_SHA"))
    if head_revision(root) != workflow_sha:
        raise PolicyError("checkout is not the exact trusted workflow commit")
    if event is None:
        try:
            with Path(env.get("GITHUB_EVENT_PATH", "")).open("rb") as stream:
                body = stream.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError()
            event = strict_json_loads(body)
        except (OSError, ValueError, PolicyError):
            raise PolicyError("GitHub event input is unavailable or invalid") from None
    try:
        def approved_repo(repo):
            return (str(repo["id"]) == rules["repository_id"] and repo["full_name"] == rules["repository"]
                    and str(repo["owner"]["id"]) == rules["repository_owner_id"])
        if not approved_repo(event["repository"]):
            raise ValueError()
        if role == "reader":
            pr = event["pull_request"]
            if (event["action"] not in ("opened", "synchronize", "reopened")
                    or not approved_repo(pr["head"]["repo"]) or not approved_repo(pr["base"]["repo"])
                    or pr["base"]["ref"] != "main"):
                raise ValueError()
            baseline, candidate = pr["base"]["sha"], pr["head"]["sha"]
        else:
            if event.get("deleted") is not False or event["ref"] != "refs/heads/main":
                raise ValueError()
            baseline, candidate = event["before"], event["after"]
            if candidate != workflow_sha or candidate != env.get("GITHUB_SHA"):
                raise ValueError()
        return require_revision(baseline), require_revision(candidate)
    except (KeyError, TypeError, ValueError):
        raise PolicyError("GitHub event is outside the reviewed same-repository source contract") from None


def token_request_url(raw, audience):
    try:
        parsed = urllib.parse.urlsplit(raw)
        if (not raw or len(raw) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in raw)
                or parsed.scheme != "https" or not parsed.hostname
                or not parsed.hostname.endswith(".actions.githubusercontent.com")
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443) or parsed.fragment):
            raise ValueError()
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if any(key == "audience" for key, _value in query):
            raise ValueError()
        return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query + [("audience", audience)])))
    except (ValueError, TypeError):
        raise PolicyError("GitHub OIDC request endpoint is invalid") from None


def checked_jwt(jwt, role, audience, workflow_sha):
    """Local consistency check only; Tailscale verifies signature, expiry and trust."""
    token_text(jwt)
    try:
        pieces = jwt.split(".")
        if len(pieces) != 3 or not all(pieces):
            raise ValueError()
        claims = strict_json_loads(base64.b64decode(pieces[1] + "=" * (-len(pieces[1]) % 4), altchars=b"-_", validate=True))
        identities, _digest = load_manifest()
        identity = identities[role]
        expected = dict(identity["customClaimRules"], iss=identity["issuer"], sub=identity["subject"], aud=audience, workflow_sha=workflow_sha)
        if not isinstance(claims, dict) or any(claims.get(key) != value for key, value in expected.items()):
            raise ValueError()
    except (ValueError, TypeError, KeyError, PolicyError):
        raise PolicyError("GitHub OIDC claims differ from the reviewed trust") from None
    return jwt


def resolve_oidc(role, environment=None):
    env = os.environ if environment is None else environment
    # Even direct library callers must pass context checks before requesting a JWT.
    trusted_context(role, env)
    client_id = identifier(env.get("TS_FEDERATED_CLIENT_ID"))
    audience = env.get("TS_FEDERATED_AUDIENCE")
    if audience != "api.tailscale.com/" + client_id:
        raise PolicyError("federated audience does not match the configured client ID")
    url = token_request_url(env.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""), audience)
    request_token = token_text(env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + request_token})
    status, body, _etag = request_bytes(request, max_response_bytes=MAX_TOKEN_BODY)
    if status != 200 or len(body) > MAX_TOKEN_BODY:
        raise PolicyError("GitHub OIDC token request failed or exceeded its response limit")
    jwt = checked_jwt(parse_object(body).get("value"), role, audience, env.get("GITHUB_WORKFLOW_SHA"))
    # The official Tailscale API expects client_id and jwt, not RFC8693 grant fields.
    data = urllib.parse.urlencode({"client_id": client_id, "jwt": jwt}).encode()
    request = urllib.request.Request(TOKEN_EXCHANGE, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    status, body, _etag = request_bytes(request, max_response_bytes=MAX_TOKEN_BODY)
    if status != 200 or len(body) > MAX_TOKEN_BODY:
        raise PolicyError("federated token exchange failed or exceeded its response limit")
    return token_text(parse_object(body).get("access_token"))
