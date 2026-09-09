# Tailnet ACL management for taila4c78d.ts.net (sulliwood.org)
#
# Usage:
#   just              # build only (default)
#   just build        # compile Dhall + merge grants
#   just validate     # compare to live ACL
#   just diff         # show what would change
#   just push <baseline-sha256> <candidate-sha256> # reviewed conditional apply
#   just fmt          # format all Dhall files

set shell := ["bash", "-euo", "pipefail", "-c"]

repo_root := justfile_directory()

# Default: build only; no live API call
default: build

# Compile Dhall to JSON and merge with grants
build:
    @python3 {{repo_root}}/scripts/build.py

# Compare committed HEAD with live Tailscale ACL, using public-safe summaries
validate:
    @python3 {{repo_root}}/scripts/validate.py

# Compare freshly compiled committed HEAD with live ACL; no raw policy output
diff:
    @python3 {{repo_root}}/scripts/push.py --dry-run

# Apply committed HEAD only when both reviewed digests and the live ETag match
[positional-arguments]
push baseline_sha256 candidate_sha256:
    @python3 {{repo_root}}/scripts/push.py --confirm --expected-live-sha256 "$1" --expected-policy-sha256 "$2"

# Format all Dhall files
fmt:
    @find {{repo_root}} -name '*.dhall' -exec dhall format --output {} {} \;
    @echo "Formatted all .dhall files"

# Type-check all Dhall files without producing output
check:
    @dhall type --file {{repo_root}}/policy.dhall > /dev/null
    @echo "Dhall type-check passed"

# Compare generated policy with a snapshot file
compare snapshot:
    @python3 -c "\
    import json; \
    a=json.load(open('{{snapshot}}')); \
    b=json.load(open('{{repo_root}}/generated/policy.json')); \
    print('MATCH' if a==b else 'MISMATCH')"

# Clean generated artifacts
clean:
    rm -rf {{repo_root}}/generated/

# Registered offline contracts; requires the repo's Dhall tools (nix develop).
test:
    python3 -m unittest discover -s tests -p 'test_*.py'

# Render one nonsecret federation request for exact review; no API calls.
identity-review role:
    python3 scripts/oidc_identity.py {{quote(role)}}
