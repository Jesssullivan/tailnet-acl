# ACL publication authority

Normal pull-request and main-push workflows build and validate source only.
They run exclusively on sanctioned `tinyland-nix` capacity and receive no
Tailscale credential or protected environment.

Repository workflow publication is confined to
`.github/workflows/publish-acl.yml`. It is manual, exact-head, digest-bound,
and protected by the
`tailnet-acl-production` environment.

## Pre-landing control-plane prerequisites

Before landing this workflow transition:

1. Permanently disable historical `.github/workflows/cd.yml` workflow ID
   `238207465`. Its source is now a tombstone, but source changes, branch
   protection, and branch deletion do not revoke the old workflow identity or
   old credentialed runs.
2. Configure `tailnet-acl-production` to allow only `main`, require an attended
   reviewer, and prevent self-review where GitHub supports it.
3. Create a read-only plan OAuth client with exactly
   `policy_file:read`, `devices:posture_attributes:read`, and
   `devices:core:read`. Store its secret as
   `TAILSCALE_ACL_READ_OAUTH_CLIENT_SECRET` and its non-secret client ID as
   `TAILSCALE_ACL_READ_OAUTH_CLIENT_ID`.
4. Create a separate apply OAuth client with exactly `policy_file`,
   `devices:posture_attributes`, and `devices:core:read`. Store its secret as
   `TAILSCALE_ACL_WRITE_OAUTH_CLIENT_SECRET` and its non-secret client ID as
   `TAILSCALE_ACL_WRITE_OAUTH_CLIENT_ID`. Do not use a broad admin API key.
5. Under a separately attended denial-proof authorization, prove that ID
   `238207465` cannot dispatch from `main` or any retained historical branch
   or tag, and that historical credentialed run `30311167574` cannot be rerun
   in whole or by failed-job replay. Require non-success API responses and no
   workflow-run-count change. Source tombstoning alone is not this proof.

## Post-landing, pre-dispatch barrier

The new `.github/workflows/publish-acl.yml` identity does not exist on the
default branch until this source lands. After landing and before any plan:

1. Record the new workflow's exact numeric ID and confirm it is `active`.
2. Reconfirm retired workflow ID `238207465` remains `disabled_manually`;
   landing its tombstone must not be allowed to re-enable that identity.
3. Reconfirm the protected environment, exact OAuth clients, and denial-proof
   evidence above are unchanged.

## Attended plan

Dispatch `Publish Tailnet ACL (attended)` from the exact current `main` commit:

- `action`: `plan`
- `expected_source_sha`: exact 40-character `main` commit
- accepted digest inputs: empty
- `confirmation`: `plan-tailnet-acl-<SHA>`

The protected job rebuilds the policy and requests an access token carrying
exactly the three read scopes above. Missing or additional returned scopes are
rejected. Before credential exchange, the publisher independently requires Git
HEAD to equal `expected_source_sha` and rejects every tracked or untracked
source change; only build output `generated/policy.json` is exempt. The job
reads the live ACL and retains the API's opaque `ETag`, then emits a non-secret
receipt containing the verified source SHA, pre-write ETag, canonical live and
generated SHA-256 digests, write-attempted flag, and outcome. Review the source
diff, ETag, and both receipt digests before authorizing publication.

## Attended apply

Dispatch the same exact `main` commit again:

- `action`: `apply`
- `expected_source_sha`: the plan's exact source commit
- `expected_live_policy_sha256`: the accepted live digest
- `expected_policy_sha256`: the accepted generated digest
- `confirmation`: `apply-tailnet-acl-<SHA>`

The publisher requests a token carrying exactly the three apply scopes above,
re-reads both policies, and refuses mutation if either digest has changed. It
retains the new GET `ETag` and sends that exact opaque value as `If-Match` on
the policy POST. HTTP 412 is classified as a confirmed no-write concurrent
change, never a successful apply.

After every non-cancelled write attempt—including HTTP 412 and other write
errors—the publisher re-reads the live policy. Its durable receipt records the
source SHA, pre/post ETags, pre/local/post canonical digests, whether a write
was attempted, and the reconciled outcome. A successful apply requires the
post-write digest to equal the accepted generated-policy digest.

The outcome keeps confirmed HTTP rejection separate from an unconfirmed 5xx or
transport response. For an ambiguous response, reconciliation reports whether
the live policy remained at the pre-write digest, equals the intended local
digest, or moved to a third digest; equality never infers which actor wrote it.

The apply command requires a receipt path. It atomically persists a
`write_attempt_pending_reconciliation` receipt before sending the POST, then
atomically replaces that receipt only after reconciliation. Failure to write
the intent receipt prevents the POST; failure to replace it cannot erase the
durable pending-attempt evidence. Each receipt write flushes and `fsync`s its
0600 temporary file before replacement, then `fsync`s the parent directory.
This is local-filesystem durability; the `always()` artifact upload remains the
separate durable off-runner copy after the step returns.

The workflow rejects every `run_attempt` after the first. Never rerun an old
publication run to apply a newer intent. Any source, live policy, credential,
environment, or workflow-identity change requires a fresh plan and a new
attended apply.
