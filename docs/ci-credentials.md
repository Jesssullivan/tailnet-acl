# CI/CD credentials for the tailnet policy

This repo pushes the live tailnet policy for `taila4c78d.ts.net`. Two GitHub
Actions jobs talk to the Tailscale API:

| Job | Workflow | Trigger | What it does |
| --- | --- | --- | --- |
| `validate` | `.github/workflows/ci.yml` | `pull_request` | Reads the live ACL, diffs it, asks Tailscale to type-check the built policy |
| `deploy` | `.github/workflows/cd.yml` | `push` to `main` | Same checks, then `POST /acl` to apply |

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
A repository-level secret of the same name is dead weight and should be deleted
so it cannot be rotated by mistake.

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

Either kind must carry the `policy_file` scope. Without it the credential
authenticates but the ACL read returns HTTP 403.

The OAuth pair is the preferred configuration: non-expiring, and scopeable to
`policy_file` alone rather than full admin.

## Rotation runbook

### Preferred: OAuth client pair

1. Tailscale admin console → **Settings → OAuth clients → Generate OAuth
   client**. Grant **only** the `policy_file` scope (read **and** write — the CD
   job pushes).
2. Copy both halves. The secret (`tskey-client-…`) is shown once.
3. GitHub → **Settings → Environments → production**:
   - **Environment secrets** → update `TAILSCALE_API_KEY` to the client secret.
   - **Environment variables** → add/update `TS_OAUTH_CLIENT_ID` to the client
     id.
4. Delete the old OAuth client in the Tailscale console.
5. Re-run CI on any open PR. `Preflight Tailscale credential wiring` proves the
   new pair before anything else runs.

### Interim: direct API key

1. Tailscale admin console → **Settings → Keys → Generate access token**.
2. GitHub → **Settings → Environments → production → Environment secrets** →
   update `TAILSCALE_API_KEY`.
3. Leave `TS_OAUTH_CLIENT_ID` unset (or accept the preflight warning that it is
   ignored).
4. Diary the 90-day expiry, or move to the OAuth pair.

Do **not** set the repository-scoped `TAILSCALE_API_KEY`. It is not read by
either job.

## What the preflight tells you

`scripts/ci_preflight.py` runs first in both jobs, on the runner's system
python3, before the Nix toolchain is installed — a dead credential costs
seconds, not a full dev-shell build followed by an opaque `API error 401`. It
never prints a credential value, only the kind inferred from the prefix.

| Symptom | Meaning | Fix |
| --- | --- | --- |
| `Tailscale credential is not wired` | `TAILSCALE_API_KEY` unset in the `production` environment | Create the environment secret |
| `Tailscale OAuth client id is missing` | Secret is `tskey-client-…`, `TS_OAUTH_CLIENT_ID` unset | Add the environment **variable** |
| `Tailscale OAuth token exchange failed` | Client id and client secret are not a matching pair | Re-copy both halves from one OAuth client |
| `…present but rejected (HTTP 401)` | Expired or revoked credential | Rotate the value |
| `…lacks policy-file permission (HTTP 403)` | Credential lacks `policy_file` scope | Regenerate with the scope |

## Server-side policy validation

`scripts/acl_validate.py` POSTs the built policy to
`POST /api/v2/tailnet/{tailnet}/acl/validate`, which type-checks it without
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

Without credentials the step emits a loud warning and skips, which only happens
locally — in CI the preflight has already failed the job.

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
