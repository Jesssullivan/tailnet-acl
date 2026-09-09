"""Review, create one identity, or read back one exact identity; never enumerate keys."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

from policy_api import API_BASE, elapsed_deadline, parse_object, request_bytes
from policy_source import PolicyError, ROOT, require_digest, strict_json_loads

MANIFEST = ROOT / "config/oidc-identities.json"
ROLES = ("reader", "writer")


def load_manifest(path=MANIFEST):
    try:
        content = Path(path).read_bytes()
        value = strict_json_loads(content)
        identities = value["identities"]
        if value["schema_version"] != 1 or not isinstance(identities, dict) or set(identities) != set(ROLES):
            raise ValueError()
        for role, item in identities.items():
            if (not isinstance(item, dict) or set(item) != {"keyType", "description", "scopes", "tags", "issuer", "subject", "customClaimRules"}
                    or not isinstance(item["description"], str) or not 1 <= len(item["description"]) <= 50
                    or not isinstance(item["customClaimRules"], dict)
                    or set(item["customClaimRules"]) != {"repository", "repository_id", "repository_owner_id", "ref", "event_name", "workflow_ref"}
                    or not isinstance(item["scopes"], list) or not all(isinstance(scope, str) for scope in item["scopes"])
                    or item["keyType"] != "federated" or item["tags"] != []
                    or item["issuer"] != "https://token.actions.githubusercontent.com"
                    or item["subject"] != "repo:Jesssullivan/tailnet-acl:environment:production"
                    or not all(isinstance(v, str) and "*" not in v for v in item["customClaimRules"].values())):
                raise ValueError()
        return identities, hashlib.sha256(content).hexdigest()
    except (OSError, KeyError, TypeError, ValueError, PolicyError):
        raise PolicyError("federated identity manifest is invalid") from None


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value):
        raise PolicyError("federated client ID is missing or invalid")
    return value


def token_text(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 65536 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise PolicyError("credential response is missing or invalid")
    return value


def checked_metadata(value, expected, role, expected_id=None):
    """Validate the entire intended trust contract before returning only public IDs."""
    client_id = identifier(value.get("id"))
    if expected_id is not None and client_id != expected_id:
        raise PolicyError("identity readback ID differs from the requested identity")
    for field in ("keyType", "description", "issuer", "subject", "customClaimRules"):
        if value.get(field) != expected[field]:
            raise PolicyError("identity metadata differs from the reviewed manifest")
    scopes = value.get("scopes")
    if (not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes)
            or sorted(scopes) != sorted(expected["scopes"])
            or value.get("tags") not in (None, [])
            or value.get("audience") != "api.tailscale.com/" + client_id):
        raise PolicyError("identity scopes, tags, or audience differ from the reviewed contract")
    return {"role": role, "client_id": client_id, "audience": value["audience"], "metadata_verified": True}


def report_created_id(role, client_id):
    print(json.dumps({"role": role, "created_id": client_id, "metadata_verified": False}, sort_keys=True), flush=True)


def manage_identity(bearer, role, expected_manifest, client_id=None, on_created=report_created_id):
    """Create once or GET one ID; no retry, list, update, revoke, or delete operation."""
    identities, digest = load_manifest()
    if role not in ROLES or require_digest(expected_manifest) != digest:
        raise PolicyError("identity manifest differs from the reviewed digest")
    expected = identities[role]
    bearer = token_text(bearer)
    headers = {"Authorization": "Bearer " + bearer, "Content-Type": "application/json"}
    if client_id is None:
        request = urllib.request.Request(API_BASE + "/keys", data=json.dumps(expected).encode(), headers=headers, method="POST")
    else:
        request = urllib.request.Request(API_BASE + "/keys/" + identifier(client_id), headers=headers)
    status, body, _etag = request_bytes(request)
    if status not in ((200, 201) if client_id is None else (200,)):
        raise PolicyError(f"identity operation failed (HTTP {status}); inspect the exact item before retry")
    value = parse_object(body)
    # Preserve the exact nonsecret handle before any remaining metadata or GET
    # failure; this is NOT a success receipt. A create is never retried here.
    if client_id is None:
        on_created(role, identifier(value.get("id")))
    result = checked_metadata(value, expected, role, client_id)
    if client_id is None:
        read = urllib.request.Request(API_BASE + "/keys/" + result["client_id"], headers=headers)
        status, body, _etag = request_bytes(read)
        if status != 200:
            raise PolicyError("identity create was not verified; inspect the exact item before retry")
        result = checked_metadata(parse_object(body), expected, role, result["client_id"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=ROLES)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--create", action="store_true", help="attended, separately reviewed one-item mutation")
    operation.add_argument("--readback", metavar="CLIENT_ID", help="bounded GET of this exact identity only")
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args()
    try:
        identities, digest = load_manifest()
        if not args.create and not args.readback:
            print(json.dumps({"manifest_sha256": digest, "request": identities[args.role]}, sort_keys=True))
            return 0
        require_digest(args.manifest_sha256)
        # Secret input is stdin only, with an elapsed bound; nothing enters argv,
        # environment, logs, shell substitution, or files. Root supplies it in RAM.
        with elapsed_deadline(20):
            bearer = sys.stdin.buffer.read(65538)
        if len(bearer) > 65537:
            raise PolicyError("credential input exceeds the limit")
        try:
            bearer = bearer.decode("ascii").removesuffix("\n")
        except UnicodeError:
            raise PolicyError("credential input is malformed") from None
        print(json.dumps(manage_identity(bearer, args.role, args.manifest_sha256, args.readback), sort_keys=True))
        return 0
    except PolicyError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
