# OpenTofu configuration for Tailscale ACL management.
#
# Reads the generated policy JSON and pushes it to Tailscale.
#
# Usage:
#   just tofu-init   # one-time
#   just tofu-plan   # preview
#   just tofu-apply  # apply

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    tailscale = {
      source  = "tailscale/tailscale"
      version = "~> 0.17"
    }
  }
}

provider "tailscale" {
  api_key = var.tailscale_api_key
  tailnet = var.tailnet
}

# Read the generated policy JSON
locals {
  policy_path = "${path.module}/../generated/policy.json"
  policy_json = file(local.policy_path)
}

# Push the ACL policy
resource "tailscale_acl" "this" {
  acl = local.policy_json
}
