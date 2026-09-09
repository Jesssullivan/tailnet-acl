# CI/CD credentials for the tailnet policy

This repo pushes the live tailnet policy for `taila4c78d.ts.net`. Two GitHub
Actions jobs talk to the Tailscale API:

| Job | Workflow | Trigger | What it does |
| --- | --- | --- | --- |
| `validate` | `.github/workflows/ci.yml` | `pull_request` | Checks exact source baseline/candidate digests and asks Tailscale to validate the candidate |
| `deploy` | `.github/workflows/cd.yml` | `push` to `main` | Same checks, then one ETag-protected `POST /acl` and fresh GET verification |

## One scope, one credential set

Both jobs declare `environment: production`. That is deliberate, and it is the
whole point of this document.

GitHub resolves `secrets.X` from the job's environment first and falls back to
the repository scope, so a repository secret and an environment secret with the
**same name** are two different values with no visible sign that they differ.
Before this was unified, `validate` read the repository-scoped
`TAILSCALE_API_KEY` and `deploy` read the `production`-scoped one. A red
`validate` therefore said nothing about whether the deploy would work, and a
rotation applied to one scope silently left the other dead.

The rule now: **the `production` environment is the only scope that matters.**
A repository-level secret of the same name is not the intended custody. Do not
delete, rotate, or replace either value without explicit per-item operator direction.

| Name | Type | Scope | Required |
| --- | --- | --- | --- |
| `TAILSCALE_API_KEY` | Environment **secret** | `production` | always |
| `TS_OAUTH_CLIENT_ID` | Environment **variable** | `production` | only when the secret is an OAuth client secret |

`TS_OAUTH_CLIENT_ID` is a *variable*, not a secret — the client id is not
sensitive, and storing it as a secret makes it unreadable in logs for no gain.
Environment variables live under
*Settings → Environments → production → Environment variables*.

## Two kinds of credential

`scripts/ts_auth.py` accepts either form in `TAILSCALE_API_KEY` and branches on
the prefix:

- **`tskey-api-…`** — a direct admin API key. Used as the bearer token as-is.
  Needs no client id. **Expires after at most 90 days**, so it guarantees a
  future outage on a timer.
- **`tskey-client-…`** — an OAuth client secret. Tailscale rejects it as a
  bearer token (HTTP 403); it is exchanged for a short-lived access token via
  the `client_credentials` grant. **Does not expire.** The exchange requires the
  client id, so `TS_OAUTH_CLIENT_ID` becomes mandatory.

The shared CI/CD credential needs `policy_file`, including its documented
`devices:posture_attributes` and `devices:core:read` dependencies. A separate
read-only validator would use `policy_file:read` with the corresponding posture
read and core read dependencies. These are distinct from the lab device
management OAuth client. See the [current scope contract](https://tailscale.com/docs/reference/trust-credentials).

The existing loader supports a direct key or an OAuth pair. A future federated
identity migration requires its own reviewed trust configuration; this flow
correction does not select or provision that migration.

## Rotation runbook

### Existing OAuth client pair interface

1. Tailscale admin console → **Settings → OAuth clients → Generate OAuth
   client**. Grant `policy_file` and its required scope dependencies (the CD
   job pushes). This creation requires an attended operator decision.
2. Copy both halves. The secret (`tskey-client-…`) is shown once.
3. GitHub → **Settings → Environments → production**:
   - **Environment secrets** → update `TAILSCALE_API_KEY` to the client secret.
   - **Environment variables** → add/update `TS_OAUTH_CLIENT_ID` to the client
     id.
4. Preserve the old credential until its retirement is separately authorized
   and the replacement has read, validation, conditional-write, and post-read proof.
5. Re-run CI on any open PR. `Preflight Tailscale credential wiring` proves the
   new pair before anything else runs.

### Interim: direct API key

1. Tailscale admin console → **Settings → Keys → Generate access token**.
2. GitHub → **Settings → Environments → production → Environment secrets** →
   update `TAILSCALE_API_KEY`.
3. `TS_OAUTH_CLIENT_ID` is not used by the direct-key path; the preflight does
   not issue an unused-variable warning.
4. Diary the 90-day expiry, or move to the OAuth pair.

Use the `production` environment for intended custody. GitHub can fall back to
a repository-scoped `TAILSCALE_API_KEY` if the environment value is absent; the
script cannot distinguish which scope supplied the resolved `secrets` value.

## What the preflight tells you

`scripts/ci_preflight.py` runs first in both jobs, on the runner's system
python3, before the Nix toolchain is installed — a dead credential costs
seconds, not a full dev-shell build followed by an opaque `API error 401`. It
prints only fixed status categories. It never prints a credential value, API
response body, or live policy.

| Report | Meaning | Next step |
| --- | --- | --- |
| `TAILSCALE_API_KEY is missing or has an unsupported credential class` | Intended production custody is absent or malformed | Inspect that environment's exact secret interface |
| `production TS_OAUTH_CLIENT_ID is missing` | An OAuth secret has no matching client ID variable | Supply the matching ID through the attended custody workflow |
| `API request failed (HTTP 401)` | Existing credential was rejected | Review and provision a working identity through an attended decision |
| `API request failed (HTTP 403)` | Existing grant does not authorize this API read | Review the intended policy scopes; do not widen a device client implicitly |
| `API request failed (transport or timeout)` | No completed read proof | Investigate connectivity; do not infer authentication success |

## Server-side policy validation

`scripts/acl_validate.py` POSTs the built policy to
`POST /api/v2/tailnet/{tailnet}/acl/validate`, which type-checks fresh committed source without
applying anything. This is the only pre-merge check that can catch a policy
Tailscale will refuse — `push.py --dry-run` merely diffs the local build against
the live ACL and never asks whether the result is legal.

The endpoint has a trap: **policy errors are returned with HTTP 200** and a
JSON body carrying `message` / `data`, matching
`tailscale.com/cmd/gitops-pusher`. A naive status-code check passes everything.
So the script treats a non-empty `message` or `data` as failure, and `--prove`
first submits a policy that must be rejected (unknown action plus an undefined
group reference). If that known-bad policy comes back clean, the checker is
blind and the step fails rather than reporting a pass it cannot justify.

Missing credentials and unavailable validation fail closed, including locally.
No raw rejection or HTTP error body is published. The detailed conditional
source/baseline and ETag contract is in [policy-delivery.md](policy-delivery.md).

## Caveats of `environment:` on a pull-request job

- **Fork PRs get no secrets.** This is GitHub behaviour for any scope, not a
  consequence of using an environment. Policy changes have to come from a
  branch on this repository.
- **Adding required reviewers to the `production` environment would gate every
  PR**, because the `validate` job would then wait for a deployment approval.
  If that protection is ever wanted for deploys only, split the environments and
  update the `environment:` key plus the `SCOPE` string in
  `scripts/ci_preflight.py` together.
- **A deployment-branch policy restricting `production` to `main` would break
  PR validation** for the same reason.
- Each PR run records a `production` deployment in the Environments UI. That is
  cosmetic noise; `validate` applies nothing.

## Observed custody failure (2026-09-09)

The existing projected legacy API credential returned HTTP 401 on a bounded
policy GET at 20:06:38 UTC. Targeted in-memory SOPS leaf comparison at 20:11:52
UTC proved that source and runtime projection were identical; the read was not
repeated. This is not evidence of a stale local projection. No policy was
retrieved, no secret value or credential digest was recorded, and no credential
was changed. The production Actions secret was last updated June 24 at the
metadata inspection, and its earlier August 27 preflight also returned 401.
Live baseline parity and conditional-write acceptance remain unproven until
working policy-scoped custody is provisioned and reviewed.

The existing lab OAuth pair was then tested directly from its targeted SOPS
leaves at 20:21:54 UTC: token exchange returned HTTP 200, the relevant returned
scopes were `devices:core` and `devices:posture_attributes`, and the policy GET
returned HTTP 403. Its existing grant therefore does not provide policy-read
authority; no scope was added and no credential was replaced.
