#!/usr/bin/env python3
"""Read-only public-safe comparison of fresh committed source and live policy."""

import argparse
import json
import os
import sys

from policy_api import fetch_live_acl
from policy_source import PolicyError, compile_revision, head_revision, public_summary, require_revision
from ts_auth import resolve_bearer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref")
    parser.add_argument("--candidate-ref")
    args = parser.parse_args()
    try:
        candidate = compile_revision(require_revision(args.candidate_ref) if args.candidate_ref is not None else head_revision())
        baseline = compile_revision(require_revision(args.baseline_ref)) if args.baseline_ref is not None else candidate
        bearer = resolve_bearer(os.environ.get("TAILSCALE_API_KEY", ""))
        live, _etag = fetch_live_acl(bearer)
        print(json.dumps(public_summary(live, candidate), sort_keys=True))
        if live == candidate or live == baseline:
            print("Validation PASSED: live policy equals the candidate or expected source baseline.")
            return 0
        print("Validation FAILED: unexpected live policy drift requires reconciliation review.", file=sys.stderr)
        return 1
    except PolicyError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
