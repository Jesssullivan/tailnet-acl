"""Trusted main-only CI driver. PR commits are data objects, never checkouts."""

import argparse
import json
import sys

from acl_validate import validate_candidate
from github_oidc import resolve_oidc, trusted_context
from policy_api import fetch_live_acl
from policy_source import PolicyError, ROOT, _run, canonical_digest, compile_revision, public_summary
from push import promote


def run(role, context_only=False):
    baseline_ref, candidate_ref = trusted_context(role)
    if context_only:
        print("Trusted workflow checkout and source event verified; no token requested.")
        return
    # Static public remote, validated full SHAs, no PR-controlled URL/ref/shell.
    # No checkout/reset, submodules, LFS, PR artifact, PR flake or PR script.
    _run(["git", "fetch", "--no-tags", "--depth=1", "https://github.com/Jesssullivan/tailnet-acl.git",
          baseline_ref, candidate_ref], ROOT)
    baseline = compile_revision(baseline_ref)
    candidate = compile_revision(candidate_ref)
    bearer = resolve_oidc(role)
    if role == "writer":
        promote(bearer, candidate, canonical_digest(baseline), canonical_digest(candidate))
        return
    validate_candidate(bearer, candidate, prove=True)
    live, _etag = fetch_live_acl(bearer)
    print(json.dumps(public_summary(live, candidate), sort_keys=True))
    if live != baseline and live != candidate:
        raise PolicyError("unexpected live policy drift requires reconciliation review")
    print("Reader validation passed: grammar proof and live baseline/candidate parity.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("reader", "writer"))
    parser.add_argument("--check-context", action="store_true")
    args = parser.parse_args()
    try:
        run(args.role, args.check_context)
        return 0
    except PolicyError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
