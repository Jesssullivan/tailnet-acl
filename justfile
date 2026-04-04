# Tailnet ACL management for taila4c78d.ts.net (sulliwood.org)
#
# Usage:
#   just              # build + validate (default)
#   just build        # compile Dhall + merge grants
#   just validate     # compare to live ACL
#   just diff         # show what would change
#   just push         # push to live (requires --confirm)
#   just fmt          # format all Dhall files

set shell := ["bash", "-euo", "pipefail", "-c"]

repo_root := justfile_directory()

# Default: build and validate
default: build

# Compile Dhall to JSON and merge with grants
build:
    @python3 {{repo_root}}/scripts/build.py

# Validate generated policy against live Tailscale ACL
validate: build
    @python3 {{repo_root}}/scripts/validate.py

# Show diff between local and live ACL (dry-run push)
diff: build
    @python3 {{repo_root}}/scripts/push.py --dry-run

# Push generated policy to live Tailscale ACL
push: build
    @python3 {{repo_root}}/scripts/push.py --confirm

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
