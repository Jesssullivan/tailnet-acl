#!/usr/bin/env python3
"""Ask Tailscale to type-check generated/policy.json without applying it.

``push.py --dry-run`` only diffs the local build against the live ACL. Nothing
in CI asks Tailscale whether the policy it is about to push is *acceptable*, so
a grammar or reference error survives review and first surfaces as a failed CD
push after merge. This closes that gap with

    POST /api/v2/tailnet/{tailnet}/acl/validate

which validates a policy server-side and applies nothing.

Response contract, mirroring tailscale.com/cmd/gitops-pusher (testNewACLs):

  - a non-2xx status is a failure;
  - a 2xx response whose body carries a non-empty ``message`` or a non-empty
    ``data`` array is ALSO a failure -- Tailscale reports policy errors with
    HTTP 200;
  - an empty body, or ``{}``, is a pass.

Because "HTTP 200" does not mean "valid" here, ``--prove`` first submits a
policy Tailscale must reject. If that known-bad policy comes back clean, this
checker cannot see failures at all, and we fail loudly rather than report a
pass we have no basis for.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ts_auth import resolve_bearer  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATED_POLICY = REPO_ROOT / "generated" / "policy.json"
TAILNET = "taila4c78d.ts.net"
API_BASE = f"https://api.tailscale.com/api/v2/tailnet/{TAILNET}"

IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"

# Two independent grammar errors: an action Tailscale does not define, and a
# reference to a group that is not declared anywhere. Used by --prove to
# confirm this checker can actually observe a rejection.
KNOWN_BAD_POLICY = {
    "acls": [
        {
            "action": "definitely-not-a-valid-action",
            "src": ["group:tailnet-acl-selftest-undefined-group"],
            "dst": ["*:*"],
        }
    ]
}


def _annotate(level: str, title: str, lines: "list[str]") -> None:
    sys.stdout.flush()
    if IN_ACTIONS:
        print(f"::{level} title={title}::{' '.join(lines)}")
    print(title, file=sys.stderr)
    for line in lines:
        print(f"  {line}", file=sys.stderr)


def post_validate(bearer: str, policy: dict) -> "tuple[int, str]":
    """POST a policy to the validate endpoint. Returns (status, body)."""
    data = json.dumps(policy).encode("utf-8")
    req = urllib.request.Request(f"{API_BASE}/acl/validate", data=data, method="POST")
    req.add_header("Authorization", f"Bearer {bearer}")
    # gitops-pusher posts a whole policy file with this content type; strict
    # JSON is valid HuJSON, so the body below is what upstream would send.
    req.add_header("Content-Type", "application/hujson")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def interpret(status: int, body: str) -> "tuple[bool, list[str]]":
    """Decide whether a /acl/validate response is a pass, and why not."""
    problems: list[str] = []
    text = body.strip()
    parsed = None

    if text:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            problems.append(f"unparseable response body: {text[:500]}")

    if isinstance(parsed, dict):
        message = parsed.get("message") or ""
        if message:
            problems.append(str(message))
        for entry in parsed.get("data") or []:
            if not isinstance(entry, dict):
                problems.append(str(entry))
                continue
            prefix = f"user {entry['user']}: " if entry.get("user") else ""
            for err in entry.get("errors") or []:
                problems.append(f"{prefix}error: {err}")
            for warning in entry.get("warnings") or []:
                problems.append(f"{prefix}warning: {warning}")
    elif parsed is not None:
        problems.append(f"unexpected response shape: {text[:500]}")

    if status // 100 != 2:
        problems.append(f"HTTP {status}")

    return (not problems), problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--prove",
        action="store_true",
        help=(
            "Before validating the real policy, submit a deliberately invalid one and "
            "require that Tailscale rejects it. Guards against reporting a vacuous pass."
        ),
    )
    args = parser.parse_args()

    secret = os.environ.get("TAILSCALE_API_KEY", "").strip()
    if not secret:
        _annotate(
            "warning",
            "Server-side ACL validation SKIPPED",
            [
                "TAILSCALE_API_KEY is not set, so the policy was not checked against the "
                "Tailscale grammar.",
                "In CI this cannot happen: scripts/ci_preflight.py fails the job first. "
                "Locally, export TAILSCALE_API_KEY to enable this check.",
            ],
        )
        return 0

    if not GENERATED_POLICY.exists():
        _annotate(
            "error",
            "Nothing to validate",
            [f"{GENERATED_POLICY} does not exist. Run 'just build' first."],
        )
        return 1

    try:
        bearer = resolve_bearer(secret)
    except Exception as exc:  # noqa: BLE001 -- surfaced verbatim to the operator
        _annotate(
            "error",
            "Tailscale token could not be resolved",
            [str(exc), "See docs/ci-credentials.md."],
        )
        return 1

    if args.prove:
        status, body = post_validate(bearer, KNOWN_BAD_POLICY)
        ok, problems = interpret(status, body)
        if status in (404, 405):
            # The endpoint is not available for this tailnet. That is not a
            # policy problem and must not fail the build -- but say so loudly,
            # because the pre-merge grammar gate is then absent.
            _annotate(
                "warning",
                "Server-side ACL validation UNAVAILABLE",
                [
                    f"POST {API_BASE}/acl/validate returned HTTP {status}, so this "
                    "tailnet does not expose the validate endpoint.",
                    "Skipping the grammar gate. Policy errors will surface at CD push "
                    "time instead of on the pull request.",
                ],
            )
            return 0
        if status // 100 != 2:
            # A transport or auth failure would also "reject" the known-bad
            # policy, which would make the self-test vacuous. Say so plainly
            # instead of claiming the validator works.
            _annotate(
                "error",
                "Could not run the ACL validator self-test",
                [
                    f"The validate endpoint returned HTTP {status}, so the self-test "
                    "proves nothing about grammar checking.",
                    f"Body: {body.strip()[:300] or '(empty)'}",
                    "This is a credential or availability problem, not a policy problem. "
                    "See docs/ci-credentials.md.",
                ],
            )
            return 1
        if ok:
            _annotate(
                "error",
                "Server-side ACL validation is blind",
                [
                    "Tailscale accepted a policy that is deliberately invalid (unknown "
                    "action plus an undefined group reference), so a clean result from "
                    "this endpoint proves nothing about the real policy.",
                    f"Endpoint returned HTTP {status} with body: {body.strip()[:300] or '(empty)'}",
                    "Refusing to report a pass. Re-check the endpoint contract before "
                    "trusting this step.",
                ],
            )
            return 1
        print("Self-test OK: the known-bad policy was rejected as expected.")
        print(f"  rejection: {problems[0][:300]}")

    policy = json.loads(GENERATED_POLICY.read_text(encoding="utf-8"))
    print(f"Validating generated/policy.json against {TAILNET} ...")
    status, body = post_validate(bearer, policy)
    ok, problems = interpret(status, body)

    if ok:
        print(f"Server-side validation PASSED (HTTP {status}).")
        return 0

    _annotate(
        "error",
        "Tailscale rejected the generated policy",
        [f"HTTP {status}."] + problems,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
