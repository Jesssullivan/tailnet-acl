# Variables for Tailscale ACL management.

variable "tailscale_api_key" {
  description = "Tailscale API key with ACL write access"
  type        = string
  sensitive   = true
  default     = ""  # Set via TF_VAR_tailscale_api_key or terraform.tfvars
}

variable "tailnet" {
  description = "Tailscale tailnet name"
  type        = string
  default     = "taila4c78d.ts.net"
}
