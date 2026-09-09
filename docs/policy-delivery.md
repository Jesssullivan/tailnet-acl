# Conditional policy delivery

The policy authority is an exact committed Dhall tree plus `grants.json`.
`generated/policy.json` remains a build artifact for structural checks and
inspection; it is never an input to credentialed validation or apply.

## Source and live baseline

PR CI compiles the exact pull-request head and base commits, validates the
candidate against Tailscale, and compares the live policy with both. Expected
candidate changes are acceptable only when live still equals the base or
already equals the candidate. Other drift fails the comparison. Main CD
compiles `github.event.before` and `github.sha` using the same compiler path.
Missing, malformed, zero, or unavailable commit IDs fail closed.

Each compilation reconstructs only committed Dhall files and grants in an
isolated temporary directory under the repository git directory, then removes
that directory. Every copied Dhall file is checked with the parser's immediate
dependency listing before resolution; only plain relative `.dhall` imports to
copied files inside that directory are supported. Environment, remote, home,
absolute, missing, escaping, and unsupported import forms fail closed. Source
subprocesses receive only PATH, fixed locale values, and an isolated cache path.
Credentialed jobs use this guarded compiler, never the ordinary artifact build.
Uncommitted edits and a stale generated artifact cannot become
the submitted policy. Public output contains canonical SHA256 digests, counts
of known sections, and fixed status text. It contains no member names, policy
values, unknown section names, credentials, or HTTP error bodies. Canonical
serialization sorts object keys with JSON separators `(',', ':')`; list order
and every policy key remain significant. Duplicate keys and nonfinite numbers
are rejected in source grants, API/OAuth replies, and validator responses.

## Conditional update

The apply command checks the candidate digest before its live read. It makes
no write when the live digest already equals the candidate. Otherwise live
must equal the reviewed baseline, and a usable strong ETag must exist. The
shared promotion path must then prove known-bad rejection and candidate grammar
acceptance, including for manual `--confirm`. The single policy POST carries the
original baseline ETag in `If-Match`. Tailscale rejects concurrent
changes with HTTP 412; the command never retries a POST. A new GET must then
match the candidate digest before success is reported. Transport uncertainty
or a failed post-read means the update is unverified and requires a fresh
read before retrying.

This follows the [official Tailscale policy client](https://github.com/tailscale/tailscale-client-go-v2/blob/main/policyfile.go)
and its [conditional-update contract](https://github.com/tailscale/tailscale/blob/main/client/tailscale/acl.go).
HTTP requests use a 20-second elapsed POSIX timer around connection and bounded
body reads, plus a socket timeout and a 4 MiB response limit. Redirects are
refused. The client fails closed outside the main thread, on an unsupported
platform, or when another caller timer is active; it restores the previous
signal handler afterward. A local trickling HTTP server is covered by the
deadline test. Source commands have 45-second subprocess limits. The validator must
reject its known-bad test and accept the candidate; missing credentials,
unavailable validation, malformed replies, or rejection responses cannot pass.

## Operator commands

Read-only comparison against committed HEAD:

```bash
just diff
just validate
```

After independent review of the committed candidate and current baseline,
manual apply requires both full canonical digests:

```bash
just push <reviewed-live-sha256> <reviewed-candidate-sha256>
```

Main CD supplies exact source revisions instead of manually entered digests.
There is no force flag or ignored-drift path. A failed baseline comparison
requires review and source convergence; do not normalize away unexpected
keys, reorder lists, or treat absent and default fields as equivalent without
an explicit, tested contract. Current live normalization parity remains
unproven while the existing production credential is rejected.

## Public CI and credential custody

CI comments contain only sanitized comparison output passed through environment
variables to `github-script`; step output is never inserted into JavaScript
source. Nix setup logs are not captured into comparison comments. Both CI and
CD retain the existing `production` credential interface documented in
[ci-credentials.md](ci-credentials.md). These changes do not provision an
identity, change credential scopes, delete or rotate a secret, or bypass an
environment approval.
