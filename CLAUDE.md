# tailnet-acl

Dhall-typed Tailscale ACL management for `taila4c78d.ts.net` (sulliwood.org).

## Quick Start

```bash
nix develop          # enter dev shell (dhall, just, tofu, python3)
just                 # build (default target)
just validate        # compare generated policy to live ACL
just diff            # show what would change
just push            # push to live (requires --confirm)
```

## Architecture

```
policy.dhall          # top-level: merges fragments, adds autoApprovers/nodeAttrs
  types/ACL.dhall     # type definitions (ACLRule, SSHRule, Fragment, Policy)
  constants.dhall     # all tags, groups, users, hosts as typed constants
  fragments/*.dhall   # composable policy fragments by domain
grants.json           # raw JSON grants (polymorphic app field, not Dhall-typed)
scripts/build.py      # dhall-to-json + merge grants + reorder keys -> generated/policy.json
scripts/validate.py   # compare generated policy to live ACL via Tailscale API
scripts/push.py       # push policy to Tailscale API (--confirm / --dry-run)
tofu/                 # OpenTofu alternative deployment path
```

## Conventions

- All tag/group/user strings defined in `constants.dhall` -- never hardcode strings in fragments
- Fragments export typed records; some use `aclsEarly`/`aclsLate` for rule ordering control
- Grants stay in `grants.json` (Dhall can't express the polymorphic `app` field cleanly)
- `generated/` is gitignored -- always regenerate with `just build`
- Rule ordering in `policy.dhall` must match live ACL exactly for clean validation

## CI/CD

- **PR**: Dhall type-check, format check, build, structural validation, validate against live ACL, PR comment with diff
- **Merge to main**: Build, validate, push to live via Tailscale API
- **Secret**: `TAILSCALE_API_KEY` in GitHub repo secrets (and `production` environment)

## Safety

- SSH rules are safety-critical -- changes can lock out remote access
- Always run `just validate` before pushing
- CD requires `production` environment approval for push
- The `--confirm` flag is required for `push.py` (no accidental pushes)

## Tailnet

- **Tailnet**: `taila4c78d.ts.net`
- **API**: `https://api.tailscale.com/api/v2/tailnet/taila4c78d.ts.net`
- **Aperture**: `ai` (100.108.97.127) -- managed AI gateway
