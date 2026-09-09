#!/usr/bin/env python3
"""Validate freshly compiled committed policy, without public policy/error disclosure."""

import argparse
import json
import os
import sys
import urllib.request

from policy_api import API_BASE, request_bytes
from policy_source import PolicyError, compile_revision, head_revision, require_revision, strict_json_loads
from ts_auth import resolve_bearer

KNOWN_BAD_POLICY = {"acls": [{"action": "definitely-not-a-valid-action", "src": ["group:tailnet-acl-selftest-undefined-group"], "dst": ["*:*"]}]}


def post_validate(bearer, policy):
    request = urllib.request.Request(API_BASE + "/acl/validate", data=json.dumps(policy).encode(), method="POST", headers={
        "Authorization": "Bearer " + bearer, "Content-Type": "application/hujson", "Accept": "application/json",
    })
    status, body, _etag = request_bytes(request, allow_error=True)
    return status, body


def interpret(status, body):
    """HTTP 200 can carry a rejection. Return only fixed-vocabulary reasons."""
    problems = []
    if body.strip():
        try:
            parsed = strict_json_loads(body)
        except PolicyError:
            problems.append("unparseable validation response")
        else:
            if not isinstance(parsed, dict) or set(parsed) - {"message", "data"}:
                problems.append("unexpected validation response shape")
            else:
                message, data = parsed.get("message"), parsed.get("data")
                if message is not None and not isinstance(message, str):
                    problems.append("unexpected validation message type")
                elif message:
                    problems.append("validation response contains a rejection message")
                if data is not None and not isinstance(data, list):
                    problems.append("unexpected validation data type")
                elif data:
                    problems.append("validation response contains rejected checks")
    if status // 100 != 2:
        problems.append(f"HTTP {status}")
    return not problems, problems


def validate_candidate(bearer, candidate, prove=True):
    if prove:
        status, body = post_validate(bearer, KNOWN_BAD_POLICY)
        ok, _problems = interpret(status, body)
        if status // 100 != 2:
            raise PolicyError(f"validator self-test unavailable (HTTP {status}); grammar proof absent")
        if ok:
            raise PolicyError("validator accepted the known-bad policy; grammar proof absent")
        if any(reason not in (
            "validation response contains a rejection message",
            "validation response contains rejected checks",
        ) for reason in _problems):
            raise PolicyError("validator self-test response is malformed; grammar proof absent")
        print("Self-test OK: known-bad policy was rejected.")
    status, body = post_validate(bearer, candidate)
    ok, problems = interpret(status, body)
    if not ok:
        raise PolicyError("server-side validation failed: " + "; ".join(problems))
    print(f"Server-side validation PASSED (HTTP {status}).")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prove", action="store_true")
    parser.add_argument("--candidate-ref")
    args = parser.parse_args()
    try:
        candidate = compile_revision(require_revision(args.candidate_ref) if args.candidate_ref is not None else head_revision())
        bearer = resolve_bearer(os.environ.get("TAILSCALE_API_KEY", "").strip())
        validate_candidate(bearer, candidate, prove=args.prove)
        return 0
    except PolicyError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
