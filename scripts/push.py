#!/usr/bin/env python3
"""Conditionally apply fresh committed policy after exact baseline proof."""

import argparse
import json
import os
import sys

from acl_validate import validate_candidate
from policy_api import fetch_live_acl, push_acl, strong_etag
from policy_source import PolicyError, canonical_digest, compile_revision, head_revision, public_summary, require_digest, require_revision
from ts_auth import resolve_bearer


def promote(bearer, candidate, expected_live, expected_candidate, dry_run=False):
    require_digest(expected_live)
    require_digest(expected_candidate)
    if canonical_digest(candidate) != expected_candidate:
        raise PolicyError("fresh candidate differs from the reviewed candidate digest")
    live, etag = fetch_live_acl(bearer)
    print(json.dumps(public_summary(live, candidate), sort_keys=True))
    if canonical_digest(live) == expected_candidate:
        print("No changes: live policy already equals the candidate.")
        return
    if canonical_digest(live) != expected_live:
        raise PolicyError("live policy differs from the expected baseline; reconciliation review required")
    strong_etag(etag)
    if dry_run:
        print("Baseline verified; dry run made no changes.")
        return
    validate_candidate(bearer, candidate, prove=True)
    # One conditional write only. A timeout or 412 never retries the POST.
    try:
        push_acl(bearer, candidate, etag)
        after, _etag = fetch_live_acl(bearer)
    except PolicyError as exc:
        raise PolicyError("update not verified; inspect with a fresh read before retry: " + str(exc)) from None
    if canonical_digest(after) != expected_candidate:
        raise PolicyError("post-write policy differs from the candidate; outcome requires review")
    print("Push verified by a fresh policy read.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--confirm", action="store_true")
    operation.add_argument("--dry-run", action="store_true")
    parser.add_argument("--baseline-ref", help="exact previous source commit; required for CD")
    parser.add_argument("--candidate-ref", help="exact candidate commit; defaults to HEAD")
    parser.add_argument("--expected-live-sha256", help="manual reviewed baseline digest")
    parser.add_argument("--expected-policy-sha256", help="manual reviewed candidate digest")
    args = parser.parse_args()
    try:
        revision = require_revision(args.candidate_ref) if args.candidate_ref is not None else head_revision()
        candidate = compile_revision(revision)
        if args.baseline_ref is not None:
            if args.expected_live_sha256 or args.expected_policy_sha256:
                raise PolicyError("choose source revisions or explicit digests, not both")
            baseline = compile_revision(require_revision(args.baseline_ref))
            expected_live, expected_candidate = canonical_digest(baseline), canonical_digest(candidate)
        else:
            expected_live, expected_candidate = args.expected_live_sha256, args.expected_policy_sha256
        if args.confirm or expected_live or expected_candidate:
            require_digest(expected_live)
            require_digest(expected_candidate)
        bearer = resolve_bearer(os.environ.get("TAILSCALE_API_KEY", ""))
        if expected_live and expected_candidate:
            promote(bearer, candidate, expected_live, expected_candidate, dry_run=not args.confirm)
        else:
            live, _etag = fetch_live_acl(bearer)
            print(json.dumps(public_summary(live, candidate), sort_keys=True))
            print("Assessment only; apply requires explicit baseline and candidate proof.")
        return 0
    except PolicyError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
