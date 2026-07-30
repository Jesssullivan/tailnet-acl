#!/usr/bin/env python3
"""Push the generated policy to the live Tailscale ACL.

Compares the generated policy with the live ACL, shows the diff,
and pushes only if --confirm is passed.

Requires: an exact-scope OAuth client secret in TAILSCALE_API_KEY
and its client ID in TS_OAUTH_CLIENT_ID
Tailnet: taila4c78d.ts.net
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATED_POLICY = REPO_ROOT / "generated" / "policy.json"
TAILNET = "taila4c78d.ts.net"
API_BASE = f"https://api.tailscale.com/api/v2/tailnet/{TAILNET}"
OAUTH_TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

PLAN_SCOPES = frozenset(
    {
        "devices:core:read",
        "devices:posture_attributes:read",
        "policy_file:read",
    }
)
APPLY_SCOPES = frozenset(
    {
        "devices:core:read",
        "devices:posture_attributes",
        "policy_file",
    }
)


@dataclass(frozen=True)
class LiveAcl:
    """One concurrency-bound observation of the live policy."""

    policy: dict
    etag: str


@dataclass(frozen=True)
class PushAttempt:
    """The server's disposition of one conditional write request."""

    outcome: str
    http_status: int | None = None


def verify_source_state(expected_source_sha: str) -> None:
    """Bind receipts to the exact clean Git source used for the build."""
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise RuntimeError("failed to inspect Git source state") from e

    if head != expected_source_sha:
        raise RuntimeError(
            f"source SHA mismatch: expected {expected_source_sha}, observed {head}"
        )

    # `just build` intentionally creates this untracked artifact before plan
    # or apply. Every tracked change and every other untracked path is source
    # drift and invalidates the receipt binding.
    allowed_generated_path = b"generated/policy.json"
    unexpected = []
    for entry in status.split(b"\0"):
        if not entry:
            continue
        path = entry[3:] if len(entry) >= 4 else entry
        if path == allowed_generated_path:
            continue
        unexpected.append(entry.decode("utf-8", errors="backslashreplace"))
    if unexpected:
        raise RuntimeError(
            "source worktree is not clean: " + ", ".join(unexpected)
        )


def resolve_scoped_bearer(secret: str, expected_scopes: frozenset[str]) -> str:
    """Exchange an OAuth client secret for one exact-scope access token."""
    if not secret.startswith("tskey-client-"):
        raise RuntimeError(
            "ACL publication requires a scoped OAuth client secret "
            "(tskey-client-...), not a broad API key"
        )

    client_id = os.environ.get("TS_OAUTH_CLIENT_ID", "")
    if not client_id:
        raise RuntimeError("TS_OAUTH_CLIENT_ID is required for OAuth token exchange")

    requested_scope = " ".join(sorted(expected_scopes))
    data = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": secret,
            "grant_type": "client_credentials",
            "scope": requested_scope,
        }
    ).encode()
    req = urllib.request.Request(OAUTH_TOKEN_URL, data=data)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode())

    token = payload.get("access_token")
    returned_scope = payload.get("scope")
    if not token:
        raise RuntimeError("OAuth token exchange returned no access_token")
    if not isinstance(returned_scope, str):
        raise RuntimeError("OAuth token exchange returned no scope")

    returned_scopes = returned_scope.split()
    if (
        len(returned_scopes) != len(set(returned_scopes))
        or set(returned_scopes) != expected_scopes
    ):
        raise RuntimeError(
            "OAuth token scope mismatch: "
            f"requested {requested_scope!r}, returned {returned_scope!r}"
        )
    return token


def fetch_live_acl(api_key: str) -> LiveAcl:
    """Fetch the current ACL together with its opaque concurrency ETag."""
    url = f"{API_BASE}/acl"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req) as resp:
            etag = resp.headers.get("ETag", "")
            if not etag:
                raise RuntimeError("Tailscale ACL GET returned no ETag")
            return LiveAcl(
                policy=json.loads(resp.read().decode()),
                etag=etag,
            )
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"ACL GET failed with HTTP {e.code}") from e


def push_acl(api_key: str, policy: dict, *, etag: str) -> PushAttempt:
    """Conditionally push an ACL policy against the exact observed ETag."""
    url = f"{API_BASE}/acl"
    data = json.dumps(policy).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    req.add_header("If-Match", etag)

    try:
        with urllib.request.urlopen(req):
            return PushAttempt("accepted")
    except urllib.error.HTTPError as e:
        status = e.code
        e.close()
        if status == 412:
            return PushAttempt("precondition_failed", http_status=status)
        print(f"Push failed (HTTP {status}).", file=sys.stderr)
        if 400 <= status < 500:
            return PushAttempt("rejected", http_status=status)
        return PushAttempt("response_ambiguous", http_status=status)
    except Exception as e:
        print(f"Push failed before a response was confirmed: {e}", file=sys.stderr)
        return PushAttempt("response_ambiguous")


def policy_sha256(policy: dict) -> str:
    """Return a deterministic digest for the semantic JSON policy."""
    canonical = json.dumps(
        policy,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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


def write_receipt(
    path: Path,
    *,
    source_sha: str,
    pre_write_etag: str,
    pre_policy_sha256: str,
    local_sha256: str,
    post_write_etag: str | None,
    post_policy_sha256: str | None,
    write_attempted: bool,
    outcome: str,
    changes: list[str],
) -> None:
    """Atomically write a non-secret plan/apply reconciliation receipt."""
    receipt = {
        "tailnet": TAILNET,
        "source_sha": source_sha,
        "pre_write_etag": pre_write_etag,
        "pre_policy_sha256": pre_policy_sha256,
        "local_policy_sha256": local_sha256,
        "post_write_etag": post_write_etag,
        "post_policy_sha256": post_policy_sha256,
        "write_attempted": write_attempted,
        "outcome": outcome,
        "changed": (
            post_policy_sha256
            if post_policy_sha256 is not None
            else pre_policy_sha256
        )
        != local_sha256,
        "changes": changes,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    os.replace(temporary, path)
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    directory = os.open(path.parent, directory_flags)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def validate_expected_digest(name: str, expected: str, actual: str) -> bool:
    """Fail closed when an accepted digest is absent, malformed, or stale."""
    if not SHA256_RE.fullmatch(expected):
        print(f"ERROR: {name} must be exactly 64 lowercase hex characters.", file=sys.stderr)
        return False
    if expected != actual:
        print(
            f"ERROR: {name} mismatch: expected {expected}, observed {actual}.",
            file=sys.stderr,
        )
        return False
    return True


def reconciled_state(
    *,
    pre_policy_sha256: str,
    local_policy_sha256: str,
    post_policy_sha256: str,
) -> str:
    """Classify the reconciled live state without inferring write authorship."""
    if post_policy_sha256 == local_policy_sha256:
        return "local_state"
    if post_policy_sha256 == pre_policy_sha256:
        return "pre_state"
    return "third_state"


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
    parser.add_argument(
        "--expect-live-sha256",
        default="",
        help="Required with --confirm: accepted digest of the live policy",
    )
    parser.add_argument(
        "--expect-policy-sha256",
        default="",
        help="Required with --confirm: accepted digest of the generated policy",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        help="Write a non-secret JSON receipt containing concurrency evidence",
    )
    parser.add_argument(
        "--source-sha",
        default="",
        help="Exact source commit recorded in --receipt",
    )
    args = parser.parse_args()

    if args.confirm and args.dry_run:
        parser.error("--confirm and --dry-run are mutually exclusive")
    if args.confirm and (
        not SHA256_RE.fullmatch(args.expect_live_sha256)
        or not SHA256_RE.fullmatch(args.expect_policy_sha256)
    ):
        parser.error(
            "--confirm requires both --expect-live-sha256 and "
            "--expect-policy-sha256 as 64 lowercase hex characters"
        )
    if args.confirm and not args.receipt:
        parser.error("--confirm requires --receipt for durable write evidence")
    if args.receipt and not SOURCE_SHA_RE.fullmatch(args.source_sha):
        parser.error("--receipt requires --source-sha as exactly 40 lowercase hex")

    if args.receipt:
        try:
            verify_source_state(args.source_sha)
        except Exception as e:
            print(f"ERROR: source binding failed: {e}", file=sys.stderr)
            return 1

    oauth_secret = os.environ.get("TAILSCALE_API_KEY")
    if not oauth_secret:
        print("ERROR: TAILSCALE_API_KEY environment variable is required.", file=sys.stderr)
        return 1
    try:
        api_key = resolve_scoped_bearer(
            oauth_secret,
            APPLY_SCOPES if args.confirm else PLAN_SCOPES,
        )
    except Exception as e:
        print(f"ERROR: failed to resolve Tailscale token: {e}", file=sys.stderr)
        return 1

    if not GENERATED_POLICY.exists():
        print(f"ERROR: {GENERATED_POLICY} does not exist. Run 'just build' first.", file=sys.stderr)
        return 1

    with open(GENERATED_POLICY) as f:
        local = json.load(f)

    print("Fetching live ACL ...", file=sys.stderr)
    try:
        pre_write = fetch_live_acl(api_key)
    except Exception as e:
        print(f"ERROR: failed to fetch live ACL: {e}", file=sys.stderr)
        return 1

    live = pre_write.policy
    live_sha256 = policy_sha256(pre_write.policy)
    local_sha256 = policy_sha256(local)
    diff_lines = summarize_diff(live, local)

    print(f"Live policy SHA-256:      {live_sha256}", file=sys.stderr)
    print(f"Generated policy SHA-256: {local_sha256}", file=sys.stderr)

    def record(
        *,
        outcome: str,
        write_attempted: bool = False,
        post_write: LiveAcl | None = None,
    ) -> None:
        if not args.receipt:
            return
        write_receipt(
            args.receipt,
            source_sha=args.source_sha,
            pre_write_etag=pre_write.etag,
            pre_policy_sha256=live_sha256,
            local_sha256=local_sha256,
            post_write_etag=post_write.etag if post_write else None,
            post_policy_sha256=(
                policy_sha256(post_write.policy) if post_write else None
            ),
            write_attempted=write_attempted,
            outcome=outcome,
            changes=diff_lines,
        )

    if args.confirm:
        expectations_match = validate_expected_digest(
            "expected live policy SHA-256",
            args.expect_live_sha256,
            live_sha256,
        )
        expectations_match = (
            validate_expected_digest(
                "expected generated policy SHA-256",
                args.expect_policy_sha256,
                local_sha256,
            )
            and expectations_match
        )
        if not expectations_match:
            record(outcome="rejected_stale_plan")
            return 3

    if live == local:
        print("No changes: local policy matches live ACL.", file=sys.stderr)
        record(outcome="already_converged")
        return 0

    print("\nChanges to apply:", file=sys.stderr)
    for line in diff_lines:
        print(f"  {line}", file=sys.stderr)

    if args.dry_run:
        print("\n(dry run, no changes made)", file=sys.stderr)
        record(outcome="plan_changes")
        return 0

    if not args.confirm:
        print(
            "\nTo apply these changes, run again with --confirm.",
            file=sys.stderr,
        )
        record(outcome="plan_changes_unconfirmed")
        return 2

    print("\nPushing policy to Tailscale API ...", file=sys.stderr)
    # Persist intent before issuing the POST. A failed atomic final receipt
    # replacement leaves this evidence intact rather than erasing the attempt.
    record(
        outcome="write_attempt_pending_reconciliation",
        write_attempted=True,
    )
    attempt = push_acl(api_key, local, etag=pre_write.etag)

    # Every non-cancelled write attempt is reconciled, even when the write
    # response is a confirmed precondition failure or another error.
    try:
        post_write = fetch_live_acl(api_key)
    except Exception as e:
        print(f"ERROR: post-attempt reconciliation failed: {e}", file=sys.stderr)
        record(
            outcome=f"{attempt.outcome}_reconciliation_failed",
            write_attempted=True,
        )
        return 1

    observed_sha256 = policy_sha256(post_write.policy)
    post_state = reconciled_state(
        pre_policy_sha256=live_sha256,
        local_policy_sha256=local_sha256,
        post_policy_sha256=observed_sha256,
    )
    if attempt.outcome == "precondition_failed":
        record(
            outcome="precondition_failed_confirmed_no_write",
            write_attempted=True,
            post_write=post_write,
        )
        print(
            "ERROR: conditional write was rejected with HTTP 412; "
            "the request made no write and live policy was reconciled.",
            file=sys.stderr,
        )
        return 4

    if attempt.outcome == "rejected":
        record(
            outcome=f"write_rejected_reconciled_{post_state}",
            write_attempted=True,
            post_write=post_write,
        )
        return 1

    if attempt.outcome == "response_ambiguous":
        record(
            outcome=f"write_response_ambiguous_reconciled_{post_state}",
            write_attempted=True,
            post_write=post_write,
        )
        return 1

    if attempt.outcome != "accepted":
        record(
            outcome=f"unknown_write_result_reconciled_{post_state}",
            write_attempted=True,
            post_write=post_write,
        )
        return 1

    if post_state != "local_state":
        record(
            outcome=f"write_accepted_reconciliation_{post_state}",
            write_attempted=True,
            post_write=post_write,
        )
        print(
            "ERROR: post-push zero-diff proof failed: "
            f"expected {local_sha256}, observed {observed_sha256}.",
            file=sys.stderr,
        )
        return 1

    record(
        outcome="write_accepted_reconciled",
        write_attempted=True,
        post_write=post_write,
    )
    print(f"Push successful; zero-diff SHA-256: {observed_sha256}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
