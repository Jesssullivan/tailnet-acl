# Federated CI/CD policy identities

The production Actions credential migration uses two independent Tailscale
federated identities. Both retain the existing `production` environment;
its protection rules are unchanged. This source does not create an identity,
set an Actions variable, delete or rotate a credential, or apply an ACL.

| Lane | Trusted workflow/event | Scopes | Production variables |
| --- | --- | --- | --- |
| Reader | `policy-validate.yml`, `pull_request_target` targeting main | `policy_file:read`, `devices:posture_attributes:read`, `devices:core:read` | `TS_POLICY_READER_CLIENT_ID`, `TS_POLICY_READER_AUDIENCE` |
| Writer | `cd.yml`, push to main | `policy_file`, `devices:posture_attributes`, `devices:core:read` | `TS_POLICY_WRITER_CLIENT_ID`, `TS_POLICY_WRITER_AUDIENCE` |

Client IDs and audiences are nonsecret variables. No Tailscale credential is
mapped from `secrets` into either workflow. The CI driver uses OIDC exclusively;
missing or incorrect variables fail closed, without a legacy credential fallback.
The existing local direct-key/OAuth interface remains for separately authorized
attended operations. Existing secrets remain untouched and must not be deleted,
rotated, or replaced without per-item operator direction.

The exact creation requests are in [oidc-identities.json](../config/oidc-identities.json).
Each identity trusts issuer `https://token.actions.githubusercontent.com`,
subject `repo:Jesssullivan/tailnet-acl:environment:production`, repository ID
`1165961732`, owner ID `37297218`, repository `Jesssullivan/tailnet-acl`, and
`refs/heads/main`. The reader additionally requires `pull_request_target` and
`Jesssullivan/tailnet-acl/.github/workflows/policy-validate.yml@refs/heads/main`;
the writer requires `push` and the corresponding exact `cd.yml` workflow ref.
There are no wildcard claims or node enrollment tags.

These scope dependencies and read-only validation authority follow the
[official scope reference](https://tailscale.com/docs/reference/trust-credentials).
The [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)
defines the repository, event, workflow and environment claims.

## Public PR execution boundary

`ci.yml` is unprivileged: contents read only, no production environment and no
OIDC permission. It can execute PR code for ordinary build/tests. It publishes
no policy artifact. Its existing required checks remain Dhall type-check/build
and secret detection.

The separate reader workflow uses `pull_request_target`. Its job condition
rejects forks and wrong repository/owner/base identities before granting an
OIDC-capable job. It checks out exactly `github.workflow_sha`, with checkout
credentials disabled. Trusted Python verifies that checkout and the platform
event again before tool installation and before requesting a JWT. It fetches
only exact validated commit IDs from the fixed public origin; it never checks
out PR commits. The guarded compiler reconstructs only committed `.dhall`
files and `grants.json` as data, checks local imports, and strips credentials
from subprocess environments. PR scripts, workflows, flakes, caches, artifacts,
submodules and hooks are never executed by the credentialed path.

Both trusted jobs use commit-pinned checkout and Nix installer actions and the
main checkout's locked Nix toolchain, with no shared Actions cache. Their
15-minute job limit bounds aggregate work; compiler subprocesses have 45-second
limits. Main is the executable trust boundary, so executable or trust changes
must receive independent source review before merging. This source does not
change branch protection or add a new required check automatically.

## Memory-only exchange

`scripts/github_oidc.py` verifies platform context, requests a GitHub JWT for
the configured audience, checks its claim consistency locally, then submits
`client_id` and `jwt` to Tailscale's `/api/v2/oauth/token-exchange`. Tailscale
performs signature, expiry and issuer/trust verification. Local claim decoding
is an additional consistency check, not cryptographic authentication.

JWT retrieval accepts only HTTPS GitHub Actions token-service subdomains, with
no redirect, credentials in the URL, fragment or preexisting audience override.
Both token responses are limited to 64 KiB and each request to 20 elapsed
seconds. JWTs and access tokens stay in the Python process; they are never
printed, written to files, passed in argv, or published through `GITHUB_ENV`,
step outputs, comments or artifacts. Logs contain fixed categories, public
policy digests and known section counts only.

## Reviewed bootstrap and attended provisioning

1. The guarded-source prerequisite #25 merged normally on September 9 at
   `6548a9c0faba909c5a10fc2f701a1ec5a3438e30`. Both required checks passed;
   the old nonrequired live-validation check failed with legacy custody.
2. Independently review the OIDC source and exact identity manifest digest.
   `just identity-review reader` and `just identity-review writer` render the
   nonsecret request bodies and manifest SHA256 without API access.
3. Only after explicit per-item root review, create each identity once using
   `scripts/oidc_identity.py ROLE --create --manifest-sha256 DIGEST`. The
   attended caller supplies its authorized admin bearer on stdin from targeted
   encrypted custody held in RAM, never from shell substitution, argv,
   environment exports, a plaintext file, or a CI secret. Library callers can
   pass the in-memory bearer to `manage_identity` and retain the nonsecret
   creation callback receipt directly. No existing credential is changed.
4. Creation makes one POST to this tailnet's `/keys`, emits a JSON receipt with
   a validated **nonsecret created ID immediately**, then verifies the complete
   returned metadata and a fresh exact-ID GET. The early receipt is marked
   `metadata_verified: false`; only the final receipt proves metadata parity.
   No retry, enumeration, update, delete or revoke operation exists. If a POST
   response is lost or its ID is invalid, creation is uncertain: do not retry;
   inspect the attended admin console for the exact description. If an ID was
   received, `ROLE --readback CLIENT_ID --manifest-sha256 DIGEST` checks only
   that item using the same bounded stdin interface.
5. Record the two verified client IDs/audiences as their respective production
   variables. Preserve the generated `api.tailscale.com/<client-id>` audience;
   no wildcard or hand-chosen audience is accepted. Setting these variables
   does not change environment protections or retire old secrets.
6. Merge the reviewed OIDC source normally after its required checks pass.
   Its first main CD should perform a bounded OIDC exchange and idempotent
   live/source comparison, because this change modifies no Dhall/grants.
   Reader proof requires a subsequent same-repository PR event after the
   trusted workflow exists on main; a fork must receive no reader job.
7. Separately review and promote any actual policy grant. Required acceptance
   is known-bad rejection, candidate grammar acceptance, baseline parity,
   one strong-ETag conditional POST if needed, and fresh post-read parity.
   An uncertain write is never retried automatically.

The official [federation documentation](https://tailscale.com/docs/features/workload-identity-federation)
provides the create and token-exchange endpoints. The
[official Go client's Key response](https://github.com/tailscale/tailscale-client-go-v2/blob/main/keys.go)
contains top-level identity fields for create and GET. The
[official provider](https://github.com/tailscale/terraform-provider-tailscale/blob/main/tailscale/resource_federated_identity.go)
explicitly identifies `id` as the client/key ID, uses that same ID for reads,
and normalizes nil tags to empty. The
[client's create test](https://github.com/tailscale/tailscale-client-go-v2/blob/main/keys_test.go)
uses HTTP 200. The utility accepts 200 or 201 for POST only, with full metadata
and GET verification in either case; 201 is compatibility behavior, not a
claimed live observation. No token response `key` field is exposed.

## Dated evidence and remaining acceptance

Earlier September 9 observations found the existing projected legacy API key
rejected with HTTP 401, its encrypted source matching the projection, and the
lab device OAuth pair exchanging successfully but receiving HTTP 403 for ACL
read. These did not prove Actions custody or justify widening that device pair.

A separately authorized attended read at **22:25:38 UTC** proved canonical
current-main/live policy parity. At **22:31:12 UTC**, the guarded validator
rejected its known-bad canary and accepted the separately reviewed grant
candidate (both HTTP 200). Neither observation applied a policy or repaired the
Actions credential. Conditional-write behavior and the new federated identities
remain unproven until their explicit live acceptance steps complete. The
existing generated artifact is preserved and excluded from all delivery.
